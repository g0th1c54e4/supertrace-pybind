#include "trace_file.h"

TraceData parse_x64dbg_trace(std::string filename) {
    std::ifstream f;
    std::uintmax_t file_size = std::filesystem::file_size(filename);

    f.open(filename, std::ios::in | std::ios::binary);
    if (!f.is_open()) {
        throw std::exception("Error opening file.");
    }

    TraceData trace_data{};
    trace_data.trace_filename = filename;

    // check magic number 'TRAC' (0x43415254)
    uint32_t magic = 0;
    f.read(reinterpret_cast<char*>(&magic), 4);
    if (magic != 0x43415254) {
        throw std::exception("Error, wrong file format.");
    }

    size_t json_metalen = 0; // JSON metadata size
    f.read(reinterpret_cast<char*>(&json_metalen), 4);
    
    // read JSON string
    std::string json_metastr(json_metalen, 0x00);
    f.read(json_metastr.data(), json_metalen);

    Json::Value json_meta;
    Json::Reader reader;
    if (!reader.parse(json_metastr, json_meta)) {
        throw std::exception("Error parse json file.");
    }

    std::string arch = json_meta["arch"].asString();
    if (arch == "x86") { trace_data.arch = TraceDataArch::X86_32; }
    else if (arch == "x64") { trace_data.arch = TraceDataArch::X86_64; }
    else {
        f.close();
        throw std::exception("Error arch.");
    }
    trace_data.ptr_size = ((trace_data.arch == TraceDataArch::X86_64) ? sizeof(uint64_t) : sizeof(uint32_t));

    trace_data.meta.arch = arch;
    trace_data.meta.filepath = json_meta["path"].asString();
    trace_data.meta.hashAlgorithm = json_meta["hashAlgorithm"].asString();
    trace_data.meta.hash = json_meta["hash"].asString();
    trace_data.meta.compression = json_meta["compression"].asString();
    trace_data.meta.version = json_meta["ver"].asInt();

    // Provide cache space to facilitate the acceleration of parsing speed
    try {
        size_t probably_ins_num = (file_size / ((trace_data.arch == TraceDataArch::X86_64) ? 40ULL : 30ULL)); // average 30 bytes(x86-32bit)/ 40 bytes(x86-64bit) -> 1 instruction
        trace_data.record.reserve(probably_ins_num);
    }
    catch (std::exception excep){
        trace_data.record.reserve(0x1000);
    }

    csh hcs;
    if (cs_open(CS_ARCH_X86, ((trace_data.arch == TraceDataArch::X86_64) ? CS_MODE_64 : CS_MODE_32), &hcs) != CS_ERR_OK) {
        throw std::exception("Open capstone instance failed.");
    }
    if (cs_option(hcs, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
        throw std::exception("Open detail mode failed.");
    }

    // Block type (0 = instruction, 0x80-0xFF = user-defined)
    uint8_t block_type = 0;
    f.read(reinterpret_cast<char*>(&block_type), 1);
    TraceRegDump32 reg_dump32{};
    TraceRegDump64 reg_dump64{};
    uint32_t inst_idx = 0;
    uint32_t current_thread_id = 0;
    while (!f.eof()) {
        // User-defined Block
        if (block_type >= 0x80 && block_type <= 0xFF) {
            uint32_t block_size = 0;
            f.read(reinterpret_cast<char*>(&block_size), 4);
            std::vector<uint8_t> block_data(block_size);
            f.read(reinterpret_cast<char*>(block_data.data()), block_size);
            // -------------------------------------
            switch (block_type) {
            case METABLOCK_TYPE:
                trace_data.user.meta = deserializeBinary<MetaBlock>(block_data);
                break;
            }
            // -------------------------------------
            f.read(reinterpret_cast<char*>(&block_type), 1);
        }

        // Instruction Block
        if (block_type == 0x00) {
            InstructionRecord inst_record{};
            uint8_t register_changes = 0; // Register change count
            f.read(reinterpret_cast<char*>(&register_changes), 1);
            uint8_t memory_accesses = 0; // Memory access count
            f.read(reinterpret_cast<char*>(&memory_accesses), 1);
            uint8_t flags_and_opcode_size = 0; // Flags
            f.read(reinterpret_cast<char*>(&flags_and_opcode_size), 1);
            uint8_t thread_id_bit = (flags_and_opcode_size >> 7) & 1; // (Flags) bit 7 = thread ID present
            uint8_t opcode_size = flags_and_opcode_size & 15;  // (Flags) bits 0-3 = opcode size

            if (thread_id_bit > 0) {
                // Optional thread ID (4 bytes)
                f.read(reinterpret_cast<char*>(&current_thread_id), 4);
            }
            inst_record.thread_id = current_thread_id;

            inst_record.bytes.resize(opcode_size); // Opcode bytes
            f.read(reinterpret_cast<char*>(inst_record.bytes.data()), opcode_size);

            /* Changed registers (index + value pairs) */
            std::vector<uint8_t> register_change_position(register_changes); // array
            std::vector<uint64_t> register_change_new_data(register_changes); // array
            for (size_t i = 0; i < register_changes; i++) {
                uint8_t reg = 0;
                f.read(reinterpret_cast<char*>(&reg), 1);
                register_change_position[i] = reg;
            }
            for (size_t i = 0; i < register_changes; i++) {
                uint64_t new_data = 0;
                f.read(reinterpret_cast<char*>(&new_data), trace_data.ptr_size);
                register_change_new_data[i] = new_data;
            }

            /* Memory access info */
            std::vector<uint8_t> memory_access_flags(memory_accesses); // flags (bit 0 = valid flag)
            std::vector<uint64_t> memory_access_addresses(memory_accesses);
            std::vector<uint64_t> memory_access_old_data(memory_accesses);
            std::vector<uint64_t> memory_access_new_data{};
            for (size_t i = 0; i < memory_accesses; i++) {
                uint8_t flag = 0;
                f.read(reinterpret_cast<char*>(&flag), 1);
                memory_access_flags[i] = flag;
            }
            for (size_t i = 0; i < memory_accesses; i++) {
                uint64_t address = 0;
                f.read(reinterpret_cast<char*>(&address), trace_data.ptr_size);
                memory_access_addresses[i] = address;
            }
            for (size_t i = 0; i < memory_accesses; i++) {
                uint64_t old_data = 0;
                f.read(reinterpret_cast<char*>(&old_data), trace_data.ptr_size);
                memory_access_old_data[i] = old_data;
            }
            for (size_t i = 0; i < memory_accesses; i++) {
                if ((memory_access_flags[i] & 1) == 0) { // check valid flag
                    uint64_t new_data = 0;
                    f.read(reinterpret_cast<char*>(&new_data), trace_data.ptr_size);
                    memory_access_new_data.push_back(new_data);
                }
            }

            /* Fill the register of the current instruction to record data */
            uint8_t reg_id = 0;
            for (size_t i = 0; i < register_change_position.size(); i++) { // trace_data.ptr_size
                uint8_t change = register_change_position[i];
                reg_id += change;
                size_t reg_offset = (reg_id + i) * trace_data.ptr_size;
                if (trace_data.arch == TraceDataArch::X86_64) {
                    if (reg_offset < sizeof(TraceRegDump64)) {
                        uint64_t* area_ptr = (uint64_t*)(((uint8_t*)&reg_dump64) + reg_offset);
                        uint64_t old_value = *area_ptr;
                        uint64_t new_value = register_change_new_data[i];
                        *area_ptr = new_value;

                        if (trace_data.record.size() >= 1) {
                            if (old_value != new_value) {
                                trace_data.record.back().reg_changes[reg_offset] = std::make_pair(old_value, new_value);
                            }
                        }
                    }
                    else {
                        throw std::exception("Offset of regdump is invaild.");
                    }
                }
                else {
                    if (reg_offset < sizeof(TraceRegDump32)) {
                        uint32_t* area_ptr = (uint32_t*)(((uint8_t*)&reg_dump32) + reg_offset);
                        uint32_t old_value = *area_ptr;
                        uint32_t new_value = static_cast<uint32_t>(register_change_new_data[i]);
                        *area_ptr = new_value;

                        if (trace_data.record.size() >= 1) {
                            if (old_value != new_value) {
                                trace_data.record.back().reg_changes[reg_offset] = std::make_pair(static_cast<uint64_t>(old_value), static_cast<uint64_t>(new_value));
                            }
                        }
                    }
                    else {
                        throw std::exception("Offset of regdump is invaild.");
                    }
                }
            }
            if (trace_data.arch == TraceDataArch::X86_64) {
                inst_record.reg_dump64 = reg_dump64;
                inst_record.ins_address = static_cast<uint64_t>(reg_dump64.regcontext.cip);
            }
            else {
                inst_record.reg_dump32 = reg_dump32;
                inst_record.ins_address = static_cast<uint64_t>(reg_dump32.regcontext.cip);
            }

            cs_insn* pcsins;
            if (cs_disasm(hcs, inst_record.bytes.data(), inst_record.bytes.size(), inst_record.ins_address, 1, &pcsins) == 0) {
                throw std::exception("Disassembly instruction failed.");
            }

            /* Fill the memory record data of the current instruction */
            size_t new_data_counter = 0;
            for (size_t i = 0; i < memory_accesses; i++) {
                MemoryAccessRecord mem_acc{};

                uint8_t flag = memory_access_flags[i];
                mem_acc.old_data = memory_access_old_data[i];

                for (size_t j = 0; j < pcsins->detail->x86.op_count; j++) {
                    if (pcsins->detail->x86.operands[j].type == X86_OP_MEM) {
                        // movs
                        if (pcsins->id == X86_INS_MOVSB || pcsins->id == X86_INS_MOVSW || pcsins->id == X86_INS_MOVSD || pcsins->id == X86_INS_MOVSQ) {
                            mem_acc.type = AccessType::WRITE;
                            mem_acc.read_and_write = true;
                        }
                        // cmps
                        else if (pcsins->id == X86_INS_CMPSB || pcsins->id == X86_INS_CMPSW || pcsins->id == X86_INS_CMPSD || pcsins->id == X86_INS_CMPSQ) {
                            mem_acc.type = AccessType::READ;
                        }

                        else if (pcsins->detail->x86.operands[j].access == cs_ac_type::CS_AC_READ) {
                            mem_acc.type = AccessType::READ;
                        }
                        else if (pcsins->detail->x86.operands[j].access == cs_ac_type::CS_AC_WRITE) {
                            mem_acc.type = AccessType::WRITE;
                        }
                        else if (pcsins->detail->x86.operands[j].access == (cs_ac_type::CS_AC_READ | cs_ac_type::CS_AC_WRITE)) {
                            mem_acc.type = AccessType::WRITE;
                            mem_acc.read_and_write = true;
                        }
                        else { continue; }

                        mem_acc.acc_size = pcsins->detail->x86.operands[j].size;
                        break;
                    }
                }
            

                if ((flag & 1) == 0) {
                    mem_acc.new_data = memory_access_new_data[new_data_counter];
                    new_data_counter += 1;
                }
                else {
                    mem_acc.overwritten_or_identical = true;
                    mem_acc.new_data = mem_acc.old_data;
                    // memory value didn't change (it is read or overwritten with identical value)
                }
                mem_acc.acc_address = memory_access_addresses[i];

                inst_record.mem_accs.push_back(mem_acc);
            }
            cs_free(pcsins, 1);

            inst_record.id = inst_idx;
            inst_record.dbg_id = inst_idx;
            trace_data.record.push_back(inst_record);
            inst_idx++;

            f.read(reinterpret_cast<char*>(&block_type), 1);
        }
    }

    trace_data.record.shrink_to_fit();
    cs_close(&hcs);
    f.close();
    return trace_data;
}

void pybind_trace(pybind11::module_& m) {
    // Litex64dbgSdkDef
    py::class_<XMMREGISTER>(m, "XMMREGISTER")
        .def_readonly("Low", &XMMREGISTER::Low)
        .def_readonly("High", &XMMREGISTER::High);

    py::class_<YMMREGISTER>(m, "YMMREGISTER")
        .def_readonly("Low", &YMMREGISTER::Low)
        .def_readonly("High", &YMMREGISTER::High);

    py::class_<X87FPU>(m, "X87FPU")
        .def_readonly("ControlWord", &X87FPU::ControlWord)
        .def_readonly("StatusWord", &X87FPU::StatusWord)
        .def_readonly("TagWord", &X87FPU::TagWord)
        .def_readonly("ErrorOffset", &X87FPU::ErrorOffset)
        .def_readonly("ErrorSelector", &X87FPU::ErrorSelector)
        .def_readonly("DataOffset", &X87FPU::DataOffset)
        .def_readonly("DataSelector", &X87FPU::DataSelector)
        .def_readonly("Cr0NpxState", &X87FPU::Cr0NpxState);

    py::class_<REGISTERCONTEXT32>(m, "REGISTERCONTEXT32")
        .def_readonly("cax", &REGISTERCONTEXT32::cax)
        .def_readonly("ccx", &REGISTERCONTEXT32::ccx)
        .def_readonly("cdx", &REGISTERCONTEXT32::cdx)
        .def_readonly("cbx", &REGISTERCONTEXT32::cbx)
        .def_readonly("csp", &REGISTERCONTEXT32::csp)
        .def_readonly("cbp", &REGISTERCONTEXT32::cbp)
        .def_readonly("csi", &REGISTERCONTEXT32::csi)
        .def_readonly("cdi", &REGISTERCONTEXT32::cdi)
        .def_readonly("cip", &REGISTERCONTEXT32::cip)
        .def_readonly("eflags", &REGISTERCONTEXT32::eflags)
        .def_readonly("gs", &REGISTERCONTEXT32::gs)
        .def_readonly("fs", &REGISTERCONTEXT32::fs)
        .def_readonly("es", &REGISTERCONTEXT32::es)
        .def_readonly("ds", &REGISTERCONTEXT32::ds)
        .def_readonly("cs", &REGISTERCONTEXT32::cs)
        .def_readonly("ss", &REGISTERCONTEXT32::ss)
        .def_readonly("dr0", &REGISTERCONTEXT32::dr0)
        .def_readonly("dr1", &REGISTERCONTEXT32::dr1)
        .def_readonly("dr2", &REGISTERCONTEXT32::dr2)
        .def_readonly("dr3", &REGISTERCONTEXT32::dr3)
        .def_readonly("dr6", &REGISTERCONTEXT32::dr6)
        .def_readonly("dr7", &REGISTERCONTEXT32::dr7)
        .def_readonly("RegisterArea", &REGISTERCONTEXT32::RegisterArea)
        .def_readonly("x87fpu", &REGISTERCONTEXT32::x87fpu)
        .def_readonly("MxCsr", &REGISTERCONTEXT32::MxCsr)
        .def_readonly("XmmRegisters", &REGISTERCONTEXT32::XmmRegisters)
        .def_readonly("YmmRegisters", &REGISTERCONTEXT32::YmmRegisters);

    py::class_<REGISTERCONTEXT64>(m, "REGISTERCONTEXT64")
        .def_readonly("cax", &REGISTERCONTEXT64::cax)
        .def_readonly("ccx", &REGISTERCONTEXT64::ccx)
        .def_readonly("cdx", &REGISTERCONTEXT64::cdx)
        .def_readonly("cbx", &REGISTERCONTEXT64::cbx)
        .def_readonly("csp", &REGISTERCONTEXT64::csp)
        .def_readonly("cbp", &REGISTERCONTEXT64::cbp)
        .def_readonly("csi", &REGISTERCONTEXT64::csi)
        .def_readonly("cdi", &REGISTERCONTEXT64::cdi)
        .def_readonly("r8", &REGISTERCONTEXT64::r8)
        .def_readonly("r9", &REGISTERCONTEXT64::r9)
        .def_readonly("r10", &REGISTERCONTEXT64::r10)
        .def_readonly("r11", &REGISTERCONTEXT64::r11)
        .def_readonly("r12", &REGISTERCONTEXT64::r12)
        .def_readonly("r13", &REGISTERCONTEXT64::r13)
        .def_readonly("r14", &REGISTERCONTEXT64::r14)
        .def_readonly("r15", &REGISTERCONTEXT64::r15)
        .def_readonly("cip", &REGISTERCONTEXT64::cip)
        .def_readonly("eflags", &REGISTERCONTEXT64::eflags)
        .def_readonly("gs", &REGISTERCONTEXT64::gs)
        .def_readonly("fs", &REGISTERCONTEXT64::fs)
        .def_readonly("es", &REGISTERCONTEXT64::es)
        .def_readonly("ds", &REGISTERCONTEXT64::ds)
        .def_readonly("cs", &REGISTERCONTEXT64::cs)
        .def_readonly("ss", &REGISTERCONTEXT64::ss)
        .def_readonly("dr0", &REGISTERCONTEXT64::dr0)
        .def_readonly("dr1", &REGISTERCONTEXT64::dr1)
        .def_readonly("dr2", &REGISTERCONTEXT64::dr2)
        .def_readonly("dr3", &REGISTERCONTEXT64::dr3)
        .def_readonly("dr6", &REGISTERCONTEXT64::dr6)
        .def_readonly("dr7", &REGISTERCONTEXT64::dr7)
        .def_readonly("RegisterArea", &REGISTERCONTEXT64::RegisterArea)
        .def_readonly("x87fpu", &REGISTERCONTEXT64::x87fpu)
        .def_readonly("MxCsr", &REGISTERCONTEXT64::MxCsr)
        .def_readonly("XmmRegisters", &REGISTERCONTEXT64::XmmRegisters)
        .def_readonly("YmmRegisters", &REGISTERCONTEXT64::YmmRegisters);

    py::class_<FLAGS>(m, "FLAGS")
        .def_readonly("c", &FLAGS::c)
        .def_readonly("p", &FLAGS::p)
        .def_readonly("a", &FLAGS::a)
        .def_readonly("z", &FLAGS::z)
        .def_readonly("s", &FLAGS::s)
        .def_readonly("t", &FLAGS::t)
        .def_readonly("i", &FLAGS::i)
        .def_readonly("d", &FLAGS::d)
        .def_readonly("o", &FLAGS::o);

    py::class_<X87FPUREGISTER>(m, "X87FPUREGISTER")
        .def_readonly("data", &X87FPUREGISTER::data)
        .def_readonly("st_value", &X87FPUREGISTER::st_value)
        .def_readonly("tag", &X87FPUREGISTER::tag);

    py::class_<MXCSRFIELDS>(m, "MXCSRFIELDS")
        .def_readonly("FZ", &MXCSRFIELDS::FZ)
        .def_readonly("PM", &MXCSRFIELDS::PM)
        .def_readonly("UM", &MXCSRFIELDS::UM)
        .def_readonly("OM", &MXCSRFIELDS::OM)
        .def_readonly("ZM", &MXCSRFIELDS::ZM)
        .def_readonly("IM", &MXCSRFIELDS::IM)
        .def_readonly("DM", &MXCSRFIELDS::DM)
        .def_readonly("DAZ", &MXCSRFIELDS::DAZ)
        .def_readonly("PE", &MXCSRFIELDS::PE)
        .def_readonly("UE", &MXCSRFIELDS::UE)
        .def_readonly("OE", &MXCSRFIELDS::OE)
        .def_readonly("ZE", &MXCSRFIELDS::ZE)
        .def_readonly("DE", &MXCSRFIELDS::DE)
        .def_readonly("IE", &MXCSRFIELDS::IE)
        .def_readonly("RC", &MXCSRFIELDS::RC);

    py::class_<X87STATUSWORDFIELDS>(m, "X87STATUSWORDFIELDS")
        .def_readonly("B", &X87STATUSWORDFIELDS::B)
        .def_readonly("C3", &X87STATUSWORDFIELDS::C3)
        .def_readonly("C2", &X87STATUSWORDFIELDS::C2)
        .def_readonly("C1", &X87STATUSWORDFIELDS::C1)
        .def_readonly("C0", &X87STATUSWORDFIELDS::C0)
        .def_readonly("ES", &X87STATUSWORDFIELDS::ES)
        .def_readonly("SF", &X87STATUSWORDFIELDS::SF)
        .def_readonly("P", &X87STATUSWORDFIELDS::P)
        .def_readonly("U", &X87STATUSWORDFIELDS::U)
        .def_readonly("O", &X87STATUSWORDFIELDS::O)
        .def_readonly("Z", &X87STATUSWORDFIELDS::Z)
        .def_readonly("D", &X87STATUSWORDFIELDS::D)
        .def_readonly("I", &X87STATUSWORDFIELDS::I)
        .def_readonly("TOP", &X87STATUSWORDFIELDS::TOP);

    py::class_<X87CONTROLWORDFIELDS>(m, "X87CONTROLWORDFIELDS")
        .def_readonly("IC", &X87CONTROLWORDFIELDS::IC)
        .def_readonly("IEM", &X87CONTROLWORDFIELDS::IEM)
        .def_readonly("PM", &X87CONTROLWORDFIELDS::PM)
        .def_readonly("UM", &X87CONTROLWORDFIELDS::UM)
        .def_readonly("OM", &X87CONTROLWORDFIELDS::OM)
        .def_readonly("ZM", &X87CONTROLWORDFIELDS::ZM)
        .def_readonly("DM", &X87CONTROLWORDFIELDS::DM)
        .def_readonly("IM", &X87CONTROLWORDFIELDS::IM)
        .def_readonly("RC", &X87CONTROLWORDFIELDS::RC)
        .def_readonly("PC", &X87CONTROLWORDFIELDS::PC);

    py::class_<LASTERROR>(m, "LASTERROR")
        .def_readonly("code", &LASTERROR::code)
        .def_readonly("name", &LASTERROR::name);

    // Trace
    py::enum_<TraceDataArch>(m, "TraceDataArch")
        .value("X86_32", TraceDataArch::X86_32)
        .value("X86_64", TraceDataArch::X86_64)
        .export_values();

    py::enum_<AccessType>(m, "AccessType")
        .value("READ", AccessType::READ)
        .value("WRITE", AccessType::WRITE)
        .export_values();

    py::class_<TraceRegDump32>(m, "TraceRegDump32")
        .def_readonly("regcontext", &TraceRegDump32::regcontext)
        .def_readonly("flags", &TraceRegDump32::flags)
        .def_readonly("x87FPURegisters", &TraceRegDump32::x87FPURegisters)
        .def_readonly("mmx", &TraceRegDump32::mmx)
        .def_readonly("MxCsrFields", &TraceRegDump32::MxCsrFields)
        .def_readonly("x87StatusWordFields", &TraceRegDump32::x87StatusWordFields)
        .def_readonly("x87ControlWordFields", &TraceRegDump32::x87ControlWordFields)
        .def_readonly("lastError", &TraceRegDump32::lastError);

    py::class_<TraceRegDump64>(m, "TraceRegDump64")
        .def_readonly("regcontext", &TraceRegDump64::regcontext)
        .def_readonly("flags", &TraceRegDump64::flags)
        .def_readonly("x87FPURegisters", &TraceRegDump64::x87FPURegisters)
        .def_readonly("mmx", &TraceRegDump64::mmx)
        .def_readonly("MxCsrFields", &TraceRegDump64::MxCsrFields)
        .def_readonly("x87StatusWordFields", &TraceRegDump64::x87StatusWordFields)
        .def_readonly("x87ControlWordFields", &TraceRegDump64::x87ControlWordFields)
        .def_readonly("lastError", &TraceRegDump64::lastError);

    py::class_<TraceJsonMetadata>(m, "TraceJsonMetadata")
        .def(py::init<>())
        .def_readwrite("arch", &TraceJsonMetadata::arch)
        .def_readwrite("filepath", &TraceJsonMetadata::filepath)
        .def_readwrite("hashAlgorithm", &TraceJsonMetadata::hashAlgorithm)
        .def_readwrite("hash", &TraceJsonMetadata::hash)
        .def_readwrite("compression", &TraceJsonMetadata::compression)
        .def_readwrite("version", &TraceJsonMetadata::version);

    py::class_<MemoryAccessRecord>(m, "MemoryAccessRecord")
        .def_readonly("type", &MemoryAccessRecord::type)
        .def_readonly("read_and_write", &MemoryAccessRecord::read_and_write)
        .def_readonly("overwritten_or_identical", &MemoryAccessRecord::overwritten_or_identical)
        .def_readonly("acc_size", &MemoryAccessRecord::acc_size)
        .def_readonly("acc_address", &MemoryAccessRecord::acc_address)
        .def_readonly("old_data", &MemoryAccessRecord::old_data)
        .def_readonly("new_data", &MemoryAccessRecord::new_data);

    py::class_<InstructionRecord>(m, "InstructionRecord")
        .def_readonly("ins_address", &InstructionRecord::ins_address)
        .def_property_readonly("bytes",
            [](const InstructionRecord& self) {
                return py::bytes(
                    reinterpret_cast<const char*>(self.bytes.data()),
                    self.bytes.size()
                );
            }
        )

        .def_readonly("reg_dump32", &InstructionRecord::reg_dump32)
        .def_readonly("reg_dump64", &InstructionRecord::reg_dump64)

        .def_readonly("mem_accs", &InstructionRecord::mem_accs)
        .def_readonly("reg_changes", &InstructionRecord::reg_changes)
        .def_readonly("thread_id", &InstructionRecord::thread_id)
        .def_readonly("id", &InstructionRecord::id)
        .def_readonly("dbg_id", &InstructionRecord::dbg_id);

    py::class_<UserInfo>(m, "UserInfo")
        .def_readonly("meta", &UserInfo::meta);

    py::class_<TraceData>(m, "TraceData")
        .def("ARCHMASK", &TraceData::ARCHMASK)
        .def_readonly("trace_filename", &TraceData::trace_filename)
        .def_readonly("meta", &TraceData::meta)
        .def_readonly("ptr_size", &TraceData::ptr_size)
        .def_readonly("arch", &TraceData::arch)
        .def_readonly("record", &TraceData::record)
        .def_readonly("user", &TraceData::user);

    m.def("parse_x64dbg_trace", &parse_x64dbg_trace,
        py::arg("filename"),
        "Parse x64dbg trace file"
    );


    // MetaBlock

    py::enum_<ThreadWaitReason>(m, "ThreadWaitReason")
        .value("_Executive", ThreadWaitReason::_Executive)
        .value("_FreePage", ThreadWaitReason::_FreePage)
        .value("_PageIn", ThreadWaitReason::_PageIn)
        .value("_PoolAllocation", ThreadWaitReason::_PoolAllocation)
        .value("_DelayExecution", ThreadWaitReason::_DelayExecution)
        .value("_Suspended", ThreadWaitReason::_Suspended)
        .value("_UserRequest", ThreadWaitReason::_UserRequest)
        .value("_WrExecutive", ThreadWaitReason::_WrExecutive)
        .value("_WrFreePage", ThreadWaitReason::_WrFreePage)
        .value("_WrPageIn", ThreadWaitReason::_WrPageIn)
        .value("_WrPoolAllocation", ThreadWaitReason::_WrPoolAllocation)
        .value("_WrDelayExecution", ThreadWaitReason::_WrDelayExecution)
        .value("_WrSuspended", ThreadWaitReason::_WrSuspended)
        .value("_WrUserRequest", ThreadWaitReason::_WrUserRequest)
        .value("_WrEventPair", ThreadWaitReason::_WrEventPair)
        .value("_WrQueue", ThreadWaitReason::_WrQueue)
        .value("_WrLpcReceive", ThreadWaitReason::_WrLpcReceive)
        .value("_WrLpcReply", ThreadWaitReason::_WrLpcReply)
        .value("_WrVirtualMemory", ThreadWaitReason::_WrVirtualMemory)
        .value("_WrPageOut", ThreadWaitReason::_WrPageOut)
        .value("_WrRendezvous", ThreadWaitReason::_WrRendezvous)
        .value("_Spare2", ThreadWaitReason::_Spare2)
        .value("_Spare3", ThreadWaitReason::_Spare3)
        .value("_Spare4", ThreadWaitReason::_Spare4)
        .value("_Spare5", ThreadWaitReason::_Spare5)
        .value("_WrCalloutStack", ThreadWaitReason::_WrCalloutStack)
        .value("_WrKernel", ThreadWaitReason::_WrKernel)
        .value("_WrResource", ThreadWaitReason::_WrResource)
        .value("_WrPushLock", ThreadWaitReason::_WrPushLock)
        .value("_WrMutex", ThreadWaitReason::_WrMutex)
        .value("_WrQuantumEnd", ThreadWaitReason::_WrQuantumEnd)
        .value("_WrDispatchInt", ThreadWaitReason::_WrDispatchInt)
        .value("_WrPreempted", ThreadWaitReason::_WrPreempted)
        .value("_WrYieldExecution", ThreadWaitReason::_WrYieldExecution)
        .value("_WrFastMutex", ThreadWaitReason::_WrFastMutex)
        .value("_WrGuardedMutex", ThreadWaitReason::_WrGuardedMutex)
        .value("_WrRundown", ThreadWaitReason::_WrRundown)
        .export_values();

    py::enum_<ThreadPriority>(m, "ThreadPriority")
        .value("_PriorityIdle", ThreadPriority::_PriorityIdle)
        .value("_PriorityAboveNormal", ThreadPriority::_PriorityAboveNormal)
        .value("_PriorityBelowNormal", ThreadPriority::_PriorityBelowNormal)
        .value("_PriorityHighest", ThreadPriority::_PriorityHighest)
        .value("_PriorityLowest", ThreadPriority::_PriorityLowest)
        .value("_PriorityNormal", ThreadPriority::_PriorityNormal)
        .value("_PriorityTimeCritical", ThreadPriority::_PriorityTimeCritical)
        .value("_PriorityUnknown", ThreadPriority::_PriorityUnknown)
        .export_values();

    py::enum_<SymbolType>(m, "SymbolType")
        .value("Function", SymbolType::Function)
        .value("Import", SymbolType::Import)
        .value("Export", SymbolType::Export)
        .export_values();

    py::class_<ThreadInfoTime>(m, "ThreadInfoTime")
        .def_readonly("user", &ThreadInfoTime::user)
        .def_readonly("kernel", &ThreadInfoTime::kernel)
        .def_readonly("creation", &ThreadInfoTime::creation);

    py::class_<ThreadInfo>(m, "ThreadInfo")
        .def_readonly("id", &ThreadInfo::id)
        .def_readonly("handle", &ThreadInfo::handle)
        .def_readonly("teb", &ThreadInfo::teb)
        .def_readonly("entry", &ThreadInfo::entry)
        .def_readonly("cip", &ThreadInfo::cip)
        .def_readonly("suspendCount", &ThreadInfo::suspendCount)
        .def_readonly("waitReason", &ThreadInfo::waitReason)
        .def_readonly("priority", &ThreadInfo::priority)
        .def_readonly("lastError", &ThreadInfo::lastError)
        .def_readonly("time", &ThreadInfo::time)
        .def_readonly("cycles", &ThreadInfo::cycles)
        .def_readonly("name", &ThreadInfo::name);

    py::class_<SymbolInfo>(m, "SymbolInfo")
        .def_readonly("mod", &SymbolInfo::mod)
        .def_readonly("name", &SymbolInfo::name)
        .def_readonly("type", &SymbolInfo::type)
        .def_readonly("rva", &SymbolInfo::rva)
        .def_readonly("va", &SymbolInfo::va);

    py::class_<MemoryMapInfoAllocation>(m, "MemoryMapInfoAllocation")
        .def_readonly("base", &MemoryMapInfoAllocation::base)
        .def_readonly("protect", &MemoryMapInfoAllocation::protect);

    py::class_<MemoryMapInfo>(m, "MemoryMapInfo")
        .def_readonly("addr", &MemoryMapInfo::addr)
        .def_readonly("size", &MemoryMapInfo::size)
        .def_readonly("protect", &MemoryMapInfo::protect)
        .def_readonly("state", &MemoryMapInfo::state)
        .def_readonly("type", &MemoryMapInfo::type)
        .def_readonly("allocation", &MemoryMapInfo::allocation)
        .def_readonly("dataValid", &MemoryMapInfo::dataValid)
        .def_property_readonly("data", [](const MemoryMapInfo& mmi) {
            return py::bytes(
                reinterpret_cast<const char*>(mmi.data.data()),
                mmi.data.size()
            );
        });

    py::class_<ModuleSectionInfo>(m, "ModuleSectionInfo")
        .def_readonly("name", &ModuleSectionInfo::name)
        .def_readonly("addr", &ModuleSectionInfo::addr)
        .def_readonly("size", &ModuleSectionInfo::size);

    py::class_<ModuleInfo>(m, "ModuleInfo")
        .def_readonly("name", &ModuleInfo::name)
        .def_readonly("path", &ModuleInfo::path)
        .def_readonly("base", &ModuleInfo::base)
        .def_readonly("size", &ModuleInfo::size)
        .def_readonly("entry", &ModuleInfo::entry)
        .def_readonly("sectionCount", &ModuleInfo::sectionCount)
        .def_readonly("sections", &ModuleInfo::sections)
        .def_readonly("isMainModule", &ModuleInfo::isMainModule);

    py::class_<SupertraceMeta>(m, "SupertraceMeta")
        .def_readonly("version", &SupertraceMeta::version)
        .def_readonly("createTimeStamp", &SupertraceMeta::createTimeStamp);

    py::class_<ProcessInfo>(m, "ProcessInfo")
        .def_readonly("id", &ProcessInfo::id)
        .def_readonly("handle", &ProcessInfo::handle)
        .def_readonly("peb", &ProcessInfo::peb);

    py::class_<MetaBlock>(m, "MetaBlock")
        .def_readonly("supertrace", &MetaBlock::supertrace)
        .def_readonly("process", &MetaBlock::process)
        .def_readonly("threads", &MetaBlock::threads)
        .def_readonly("symbols", &MetaBlock::symbols)
        .def_readonly("memoryMaps", &MetaBlock::memoryMaps)
        .def_readonly("modules", &MetaBlock::modules)
        .def_property_readonly("exeBuf", [](const MetaBlock& mb) {
                return py::bytes(
                    reinterpret_cast<const char*>(mb.exeBuf.data()),
                    mb.exeBuf.size()
                );
            }
        );
}