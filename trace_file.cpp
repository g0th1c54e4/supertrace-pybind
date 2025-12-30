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
        .def_readwrite("Low", &XMMREGISTER::Low)
        .def_readwrite("High", &XMMREGISTER::High);

    py::class_<YMMREGISTER>(m, "YMMREGISTER")
        .def_readwrite("Low", &YMMREGISTER::Low)
        .def_readwrite("High", &YMMREGISTER::High);

    py::class_<X87FPU>(m, "X87FPU")
        .def_readwrite("ControlWord", &X87FPU::ControlWord)
        .def_readwrite("StatusWord", &X87FPU::StatusWord)
        .def_readwrite("TagWord", &X87FPU::TagWord)
        .def_readwrite("ErrorOffset", &X87FPU::ErrorOffset)
        .def_readwrite("ErrorSelector", &X87FPU::ErrorSelector)
        .def_readwrite("DataOffset", &X87FPU::DataOffset)
        .def_readwrite("DataSelector", &X87FPU::DataSelector)
        .def_readwrite("Cr0NpxState", &X87FPU::Cr0NpxState);

    py::class_<REGISTERCONTEXT32>(m, "REGISTERCONTEXT32")
        .def_readwrite("cax", &REGISTERCONTEXT32::cax)
        .def_readwrite("ccx", &REGISTERCONTEXT32::ccx)
        .def_readwrite("cdx", &REGISTERCONTEXT32::cdx)
        .def_readwrite("cbx", &REGISTERCONTEXT32::cbx)
        .def_readwrite("csp", &REGISTERCONTEXT32::csp)
        .def_readwrite("cbp", &REGISTERCONTEXT32::cbp)
        .def_readwrite("csi", &REGISTERCONTEXT32::csi)
        .def_readwrite("cdi", &REGISTERCONTEXT32::cdi)
        .def_readwrite("cip", &REGISTERCONTEXT32::cip)
        .def_readwrite("eflags", &REGISTERCONTEXT32::eflags)
        .def_readwrite("gs", &REGISTERCONTEXT32::gs)
        .def_readwrite("fs", &REGISTERCONTEXT32::fs)
        .def_readwrite("es", &REGISTERCONTEXT32::es)
        .def_readwrite("ds", &REGISTERCONTEXT32::ds)
        .def_readwrite("cs", &REGISTERCONTEXT32::cs)
        .def_readwrite("ss", &REGISTERCONTEXT32::ss)
        .def_readwrite("dr0", &REGISTERCONTEXT32::dr0)
        .def_readwrite("dr1", &REGISTERCONTEXT32::dr1)
        .def_readwrite("dr2", &REGISTERCONTEXT32::dr2)
        .def_readwrite("dr3", &REGISTERCONTEXT32::dr3)
        .def_readwrite("dr6", &REGISTERCONTEXT32::dr6)
        .def_readwrite("dr7", &REGISTERCONTEXT32::dr7)
        .def_property("RegisterArea", [](const REGISTERCONTEXT32& self) {
                py::list ret(80);
                for (size_t i = 0; i < 80; i++) {
                    ret[i] = self.RegisterArea[i];
                }
                return ret;
            }, [](REGISTERCONTEXT32& self, py::sequence seq) {
                if (seq.size() != 80)
                    throw std::runtime_error("RegisterArea must have length 80");
                for (size_t i = 0; i < 80; i++) {
                    self.RegisterArea[i] = seq[i].cast<BYTE>();
                }
            }
        )
        .def_readwrite("x87fpu", &REGISTERCONTEXT32::x87fpu)
        .def_readwrite("MxCsr", &REGISTERCONTEXT32::MxCsr)
        .def_property_readonly("XmmRegisters", [](const REGISTERCONTEXT32& self) {
            auto ls = py::list(8);
            for (size_t i = 0; i < 8; i++) ls[i] = self.XmmRegisters[i];
            return ls;
        })
        .def_property_readonly("YmmRegisters", [](const REGISTERCONTEXT32& self) {
            auto ls = py::list(8);
            for (size_t i = 0; i < 8; i++) ls[i] = self.YmmRegisters[i];
            return ls;
        });

    py::class_<REGISTERCONTEXT64>(m, "REGISTERCONTEXT64")
        .def_readwrite("cax", &REGISTERCONTEXT64::cax)
        .def_readwrite("ccx", &REGISTERCONTEXT64::ccx)
        .def_readwrite("cdx", &REGISTERCONTEXT64::cdx)
        .def_readwrite("cbx", &REGISTERCONTEXT64::cbx)
        .def_readwrite("csp", &REGISTERCONTEXT64::csp)
        .def_readwrite("cbp", &REGISTERCONTEXT64::cbp)
        .def_readwrite("csi", &REGISTERCONTEXT64::csi)
        .def_readwrite("cdi", &REGISTERCONTEXT64::cdi)
        .def_readwrite("r8", &REGISTERCONTEXT64::r8)
        .def_readwrite("r9", &REGISTERCONTEXT64::r9)
        .def_readwrite("r10", &REGISTERCONTEXT64::r10)
        .def_readwrite("r11", &REGISTERCONTEXT64::r11)
        .def_readwrite("r12", &REGISTERCONTEXT64::r12)
        .def_readwrite("r13", &REGISTERCONTEXT64::r13)
        .def_readwrite("r14", &REGISTERCONTEXT64::r14)
        .def_readwrite("r15", &REGISTERCONTEXT64::r15)
        .def_readwrite("cip", &REGISTERCONTEXT64::cip)
        .def_readwrite("eflags", &REGISTERCONTEXT64::eflags)
        .def_readwrite("gs", &REGISTERCONTEXT64::gs)
        .def_readwrite("fs", &REGISTERCONTEXT64::fs)
        .def_readwrite("es", &REGISTERCONTEXT64::es)
        .def_readwrite("ds", &REGISTERCONTEXT64::ds)
        .def_readwrite("cs", &REGISTERCONTEXT64::cs)
        .def_readwrite("ss", &REGISTERCONTEXT64::ss)
        .def_readwrite("dr0", &REGISTERCONTEXT64::dr0)
        .def_readwrite("dr1", &REGISTERCONTEXT64::dr1)
        .def_readwrite("dr2", &REGISTERCONTEXT64::dr2)
        .def_readwrite("dr3", &REGISTERCONTEXT64::dr3)
        .def_readwrite("dr6", &REGISTERCONTEXT64::dr6)
        .def_readwrite("dr7", &REGISTERCONTEXT64::dr7)
        .def_property("RegisterArea", [](REGISTERCONTEXT64& self) {
            py::list ret(80);
            for (size_t i = 0; i < 80; i++) {
                ret[i] = self.RegisterArea[i];
            }
            return ret;
        }
            , [](REGISTERCONTEXT64& self, py::sequence seq) {
                if (seq.size() != 80)
                    throw std::runtime_error("RegisterArea must have length 80");
                for (size_t i = 0; i < 80; i++) {
                    self.RegisterArea[i] = seq[i].cast<BYTE>();
                }
            })
        .def_readwrite("x87fpu", &REGISTERCONTEXT64::x87fpu)
        .def_readwrite("MxCsr", &REGISTERCONTEXT64::MxCsr)
        .def_property_readonly("XmmRegisters", [](const REGISTERCONTEXT64& self) {
            auto ls = py::list(16);
            for (size_t i = 0; i < 16; i++) ls[i] = self.XmmRegisters[i];
            return ls;
        })
        .def_property_readonly("YmmRegisters", [](const REGISTERCONTEXT64& self) {
            auto ls = py::list(16);
            for (size_t i = 0; i < 16; i++) ls[i] = self.YmmRegisters[i];
            return ls;
        });

    py::class_<FLAGS>(m, "FLAGS")
        .def_readwrite("c", &FLAGS::c)
        .def_readwrite("p", &FLAGS::p)
        .def_readwrite("a", &FLAGS::a)
        .def_readwrite("z", &FLAGS::z)
        .def_readwrite("s", &FLAGS::s)
        .def_readwrite("t", &FLAGS::t)
        .def_readwrite("i", &FLAGS::i)
        .def_readwrite("d", &FLAGS::d)
        .def_readwrite("o", &FLAGS::o);

    py::class_<X87FPUREGISTER>(m, "X87FPUREGISTER")
        .def_property_readonly("data", [](const X87FPUREGISTER& self) {
            return py::bytes(reinterpret_cast<const char*>(self.data), 10);
            }
        )
        .def_readwrite("st_value", &X87FPUREGISTER::st_value)
        .def_readwrite("tag", &X87FPUREGISTER::tag);

    py::class_<MXCSRFIELDS>(m, "MXCSRFIELDS")
        .def_readwrite("FZ", &MXCSRFIELDS::FZ)
        .def_readwrite("PM", &MXCSRFIELDS::PM)
        .def_readwrite("UM", &MXCSRFIELDS::UM)
        .def_readwrite("OM", &MXCSRFIELDS::OM)
        .def_readwrite("ZM", &MXCSRFIELDS::ZM)
        .def_readwrite("IM", &MXCSRFIELDS::IM)
        .def_readwrite("DM", &MXCSRFIELDS::DM)
        .def_readwrite("DAZ", &MXCSRFIELDS::DAZ)
        .def_readwrite("PE", &MXCSRFIELDS::PE)
        .def_readwrite("UE", &MXCSRFIELDS::UE)
        .def_readwrite("OE", &MXCSRFIELDS::OE)
        .def_readwrite("ZE", &MXCSRFIELDS::ZE)
        .def_readwrite("DE", &MXCSRFIELDS::DE)
        .def_readwrite("IE", &MXCSRFIELDS::IE)
        .def_readwrite("RC", &MXCSRFIELDS::RC);

    py::class_<X87STATUSWORDFIELDS>(m, "X87STATUSWORDFIELDS")
        .def_readwrite("B", &X87STATUSWORDFIELDS::B)
        .def_readwrite("C3", &X87STATUSWORDFIELDS::C3)
        .def_readwrite("C2", &X87STATUSWORDFIELDS::C2)
        .def_readwrite("C1", &X87STATUSWORDFIELDS::C1)
        .def_readwrite("C0", &X87STATUSWORDFIELDS::C0)
        .def_readwrite("ES", &X87STATUSWORDFIELDS::ES)
        .def_readwrite("SF", &X87STATUSWORDFIELDS::SF)
        .def_readwrite("P", &X87STATUSWORDFIELDS::P)
        .def_readwrite("U", &X87STATUSWORDFIELDS::U)
        .def_readwrite("O", &X87STATUSWORDFIELDS::O)
        .def_readwrite("Z", &X87STATUSWORDFIELDS::Z)
        .def_readwrite("D", &X87STATUSWORDFIELDS::D)
        .def_readwrite("I", &X87STATUSWORDFIELDS::I)
        .def_readwrite("TOP", &X87STATUSWORDFIELDS::TOP);

    py::class_<X87CONTROLWORDFIELDS>(m, "X87CONTROLWORDFIELDS")
        .def_readwrite("IC", &X87CONTROLWORDFIELDS::IC)
        .def_readwrite("IEM", &X87CONTROLWORDFIELDS::IEM)
        .def_readwrite("PM", &X87CONTROLWORDFIELDS::PM)
        .def_readwrite("UM", &X87CONTROLWORDFIELDS::UM)
        .def_readwrite("OM", &X87CONTROLWORDFIELDS::OM)
        .def_readwrite("ZM", &X87CONTROLWORDFIELDS::ZM)
        .def_readwrite("DM", &X87CONTROLWORDFIELDS::DM)
        .def_readwrite("IM", &X87CONTROLWORDFIELDS::IM)
        .def_readwrite("RC", &X87CONTROLWORDFIELDS::RC)
        .def_readwrite("PC", &X87CONTROLWORDFIELDS::PC);

    py::class_<LASTERROR>(m, "LASTERROR")
        .def_readwrite("code", &LASTERROR::code)
        .def_property_readonly("name", [](const LASTERROR& self) {
            return py::bytes(const_cast<const char*>(self.name), 128);
            }
        );

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
        .def_readwrite("regcontext", &TraceRegDump32::regcontext)
        .def_readwrite("flags", &TraceRegDump32::flags)
        .def_property_readonly("x87FPURegisters", [](const TraceRegDump32& self) {
            auto ls = py::list(8);
            for (size_t i = 0; i < 8; i++) ls[i] = self.x87FPURegisters[i];
            return ls;
        })
        .def_property_readonly("mmx", [](const TraceRegDump32& self) {
            auto ls = py::list(8);
            for (size_t i = 0; i < 8; i++) ls[i] = self.mmx[i];
            return ls;
        })
        .def_readwrite("MxCsrFields", &TraceRegDump32::MxCsrFields)
        .def_readwrite("x87StatusWordFields", &TraceRegDump32::x87StatusWordFields)
        .def_readwrite("x87ControlWordFields", &TraceRegDump32::x87ControlWordFields)
        .def_readwrite("lastError", &TraceRegDump32::lastError);

    py::class_<TraceRegDump64>(m, "TraceRegDump64")
        .def_readwrite("regcontext", &TraceRegDump64::regcontext)
        .def_readwrite("flags", &TraceRegDump64::flags)
        .def_property_readonly("x87FPURegisters", [](const TraceRegDump64& self) {
            auto ls = py::list(8);
            for (size_t i = 0; i < 8; i++) ls[i] = self.x87FPURegisters[i];
            return ls;
        })
        .def_property_readonly("mmx", [](const TraceRegDump64& self) {
            auto ls = py::list(8);
            for (size_t i = 0; i < 8; i++) ls[i] = self.mmx[i];
            return ls;
        })
        .def_readwrite("MxCsrFields", &TraceRegDump64::MxCsrFields)
        .def_readwrite("x87StatusWordFields", &TraceRegDump64::x87StatusWordFields)
        .def_readwrite("x87ControlWordFields", &TraceRegDump64::x87ControlWordFields)
        .def_readwrite("lastError", &TraceRegDump64::lastError);

    py::class_<TraceJsonMetadata>(m, "TraceJsonMetadata")
        .def(py::init<>())
        .def_readwrite("arch", &TraceJsonMetadata::arch)
        .def_readwrite("filepath", &TraceJsonMetadata::filepath)
        .def_readwrite("hashAlgorithm", &TraceJsonMetadata::hashAlgorithm)
        .def_readwrite("hash", &TraceJsonMetadata::hash)
        .def_readwrite("compression", &TraceJsonMetadata::compression)
        .def_readwrite("version", &TraceJsonMetadata::version);

    py::class_<MemoryAccessRecord>(m, "MemoryAccessRecord")
        .def_readwrite("type", &MemoryAccessRecord::type)
        .def_readwrite("read_and_write", &MemoryAccessRecord::read_and_write)
        .def_readwrite("overwritten_or_identical", &MemoryAccessRecord::overwritten_or_identical)
        .def_readwrite("acc_size", &MemoryAccessRecord::acc_size)
        .def_readwrite("acc_address", &MemoryAccessRecord::acc_address)
        .def_readwrite("old_data", &MemoryAccessRecord::old_data)
        .def_readwrite("new_data", &MemoryAccessRecord::new_data);

    py::class_<InstructionRecord>(m, "InstructionRecord")
        .def_readwrite("ins_address", &InstructionRecord::ins_address)
        .def_property("bytes",
            [](const InstructionRecord& self) {
                return py::bytes(
                    reinterpret_cast<const char*>(self.bytes.data()),
                    self.bytes.size()
                );
            }, [](InstructionRecord& self, py::bytes bys) {
                std::string tmp = bys;
                self.bytes.assign(tmp.begin(), tmp.end());
            }
        )

        .def_readwrite("reg_dump32", &InstructionRecord::reg_dump32)
        .def_readwrite("reg_dump64", &InstructionRecord::reg_dump64)
        .def_property("mem_accs", [](const InstructionRecord& ins) {
            py::list ls(ins.mem_accs.size()); size_t lssize = ls.size();
            for (size_t i = 0; i < lssize; i++) ls[i] = ins.mem_accs[i];
            return ls;
        }, nullptr)
        .def_readwrite("reg_changes", &InstructionRecord::reg_changes)
        .def_readwrite("thread_id", &InstructionRecord::thread_id)
        .def_readwrite("id", &InstructionRecord::id)
        .def_readwrite("dbg_id", &InstructionRecord::dbg_id);

    py::class_<UserInfo>(m, "UserInfo")
        .def_readwrite("meta", &UserInfo::meta);

    py::class_<TraceData>(m, "TraceData")
        .def("ARCHMASK", &TraceData::ARCHMASK)
        .def_readwrite("trace_filename", &TraceData::trace_filename)
        .def_readwrite("meta", &TraceData::meta)
        .def_readwrite("ptr_size", &TraceData::ptr_size)
        .def_readwrite("arch", &TraceData::arch)
        .def("getRecord", [](const TraceData& trace) {
            py::list ls(trace.record.size()); size_t lssize = ls.size();
            for (size_t i = 0; i < lssize; i++) ls[i] = trace.record[i]; 
            return ls;
        })
        .def_readwrite("user", &TraceData::user);

    m.def("parse_x64dbg_trace", &parse_x64dbg_trace,
        py::arg("filename"),
        "Parse x64dbg trace file"
    );


    // MetaBlock

    py::enum_<ThreadWaitReason>(m, "ThreadWaitReason")
        .value("Executive", ThreadWaitReason::_Executive)
        .value("FreePage", ThreadWaitReason::_FreePage)
        .value("PageIn", ThreadWaitReason::_PageIn)
        .value("PoolAllocation", ThreadWaitReason::_PoolAllocation)
        .value("DelayExecution", ThreadWaitReason::_DelayExecution)
        .value("Suspended", ThreadWaitReason::_Suspended)
        .value("UserRequest", ThreadWaitReason::_UserRequest)
        .value("WrExecutive", ThreadWaitReason::_WrExecutive)
        .value("WrFreePage", ThreadWaitReason::_WrFreePage)
        .value("WrPageIn", ThreadWaitReason::_WrPageIn)
        .value("WrPoolAllocation", ThreadWaitReason::_WrPoolAllocation)
        .value("WrDelayExecution", ThreadWaitReason::_WrDelayExecution)
        .value("WrSuspended", ThreadWaitReason::_WrSuspended)
        .value("WrUserRequest", ThreadWaitReason::_WrUserRequest)
        .value("WrEventPair", ThreadWaitReason::_WrEventPair)
        .value("WrQueue", ThreadWaitReason::_WrQueue)
        .value("WrLpcReceive", ThreadWaitReason::_WrLpcReceive)
        .value("WrLpcReply", ThreadWaitReason::_WrLpcReply)
        .value("WrVirtualMemory", ThreadWaitReason::_WrVirtualMemory)
        .value("WrPageOut", ThreadWaitReason::_WrPageOut)
        .value("WrRendezvous", ThreadWaitReason::_WrRendezvous)
        .value("Spare2", ThreadWaitReason::_Spare2)
        .value("Spare3", ThreadWaitReason::_Spare3)
        .value("Spare4", ThreadWaitReason::_Spare4)
        .value("Spare5", ThreadWaitReason::_Spare5)
        .value("WrCalloutStack", ThreadWaitReason::_WrCalloutStack)
        .value("WrKernel", ThreadWaitReason::_WrKernel)
        .value("WrResource", ThreadWaitReason::_WrResource)
        .value("WrPushLock", ThreadWaitReason::_WrPushLock)
        .value("WrMutex", ThreadWaitReason::_WrMutex)
        .value("WrQuantumEnd", ThreadWaitReason::_WrQuantumEnd)
        .value("WrDispatchInt", ThreadWaitReason::_WrDispatchInt)
        .value("WrPreempted", ThreadWaitReason::_WrPreempted)
        .value("WrYieldExecution", ThreadWaitReason::_WrYieldExecution)
        .value("WrFastMutex", ThreadWaitReason::_WrFastMutex)
        .value("WrGuardedMutex", ThreadWaitReason::_WrGuardedMutex)
        .value("WrRundown", ThreadWaitReason::_WrRundown)
        .export_values();

    py::enum_<ThreadPriority>(m, "ThreadPriority")
        .value("PriorityIdle", ThreadPriority::_PriorityIdle)
        .value("PriorityAboveNormal", ThreadPriority::_PriorityAboveNormal)
        .value("PriorityBelowNormal", ThreadPriority::_PriorityBelowNormal)
        .value("PriorityHighest", ThreadPriority::_PriorityHighest)
        .value("PriorityLowest", ThreadPriority::_PriorityLowest)
        .value("PriorityNormal", ThreadPriority::_PriorityNormal)
        .value("PriorityTimeCritical", ThreadPriority::_PriorityTimeCritical)
        .value("PriorityUnknown", ThreadPriority::_PriorityUnknown)
        .export_values();

    py::enum_<SymbolType>(m, "SymbolType")
        .value("Function", SymbolType::Function)
        .value("Import", SymbolType::Import)
        .value("Export", SymbolType::Export)
        .export_values();

    py::class_<ThreadInfoTime>(m, "ThreadInfoTime")
        .def_readwrite("user", &ThreadInfoTime::user)
        .def_readwrite("kernel", &ThreadInfoTime::kernel)
        .def_readwrite("creation", &ThreadInfoTime::creation);

    py::class_<ThreadInfo>(m, "ThreadInfo")
        .def_readwrite("id", &ThreadInfo::id)
        .def_readwrite("handle", &ThreadInfo::handle)
        .def_readwrite("teb", &ThreadInfo::teb)
        .def_readwrite("entry", &ThreadInfo::entry)
        .def_readwrite("cip", &ThreadInfo::cip)
        .def_readwrite("suspendCount", &ThreadInfo::suspendCount)
        .def_readwrite("waitReason", &ThreadInfo::waitReason)
        .def_readwrite("priority", &ThreadInfo::priority)
        .def_readwrite("lastError", &ThreadInfo::lastError)
        .def_readwrite("time", &ThreadInfo::time)
        .def_readwrite("cycles", &ThreadInfo::cycles)
        .def_readwrite("name", &ThreadInfo::name);

    py::class_<SymbolInfo>(m, "SymbolInfo")
        .def_readwrite("mod", &SymbolInfo::mod)
        .def_readwrite("name", &SymbolInfo::name)
        .def_readwrite("type", &SymbolInfo::type)
        .def_readwrite("rva", &SymbolInfo::rva)
        .def_readwrite("va", &SymbolInfo::va);

    py::class_<MemoryMapInfoAllocation>(m, "MemoryMapInfoAllocation")
        .def_readwrite("base", &MemoryMapInfoAllocation::base)
        .def_readwrite("protect", &MemoryMapInfoAllocation::protect);

    py::class_<MemoryMapInfo>(m, "MemoryMapInfo")
        .def_readwrite("addr", &MemoryMapInfo::addr)
        .def_readwrite("size", &MemoryMapInfo::size)
        .def_readwrite("protect", &MemoryMapInfo::protect)
        .def_readwrite("state", &MemoryMapInfo::state)
        .def_readwrite("type", &MemoryMapInfo::type)
        .def_readwrite("allocation", &MemoryMapInfo::allocation)
        .def_readwrite("dataValid", &MemoryMapInfo::dataValid)
        .def_property("data", [](const MemoryMapInfo& mmi) {
            return py::bytes(
                reinterpret_cast<const char*>(mmi.data.data()),
                mmi.data.size()
            );
        }, [](MemoryMapInfo& self, py::bytes bys) {
            std::string tmp = bys;
            self.data.assign(tmp.begin(), tmp.end());
        }
        );

    py::class_<ModuleSectionInfo>(m, "ModuleSectionInfo")
        .def_readwrite("name", &ModuleSectionInfo::name)
        .def_readwrite("addr", &ModuleSectionInfo::addr)
        .def_readwrite("size", &ModuleSectionInfo::size);

    py::class_<ModuleInfo>(m, "ModuleInfo")
        .def_readwrite("name", &ModuleInfo::name)
        .def_readwrite("path", &ModuleInfo::path)
        .def_readwrite("base", &ModuleInfo::base)
        .def_readwrite("size", &ModuleInfo::size)
        .def_readwrite("entry", &ModuleInfo::entry)
        .def_readwrite("sectionCount", &ModuleInfo::sectionCount)
        .def("getSections", [](const ModuleInfo& mod) {
            py::list ls(mod.sections.size()); size_t lssize = ls.size();
            for (size_t i = 0; i < lssize; i++) ls[i] = mod.sections[i];
            return ls;
        })
        .def_readwrite("isMainModule", &ModuleInfo::isMainModule);

    py::class_<SupertraceMeta>(m, "SupertraceMeta")
        .def_readwrite("version", &SupertraceMeta::version)
        .def_readwrite("createTimeStamp", &SupertraceMeta::createTimeStamp);

    py::class_<ProcessInfo>(m, "ProcessInfo")
        .def_readwrite("id", &ProcessInfo::id)
        .def_readwrite("handle", &ProcessInfo::handle)
        .def_readwrite("peb", &ProcessInfo::peb);

    py::class_<MetaBlock>(m, "MetaBlock")
        .def_readwrite("supertrace", &MetaBlock::supertrace)
        .def_readwrite("process", &MetaBlock::process)
        .def("getThreads", [](const MetaBlock& mb){
            py::list ls(mb.threads.size()); size_t lssize = ls.size();
            for (size_t i = 0; i < lssize; i++) ls[i] = mb.threads[i];
            return ls;
        })
        .def("getSymbols", [](const MetaBlock& mb) {
            py::list ls(mb.symbols.size()); size_t lssize = ls.size();
            for (size_t i = 0; i < lssize; i++) ls[i] = mb.symbols[i];
            return ls;
        })
        .def("getMemoryMaps", [](const MetaBlock& mb) {
            py::list ls(mb.memoryMaps.size()); size_t lssize = ls.size();
            for (size_t i = 0; i < lssize; i++) ls[i] = mb.memoryMaps[i];
            return ls;
        })
        .def("getModules", [](const MetaBlock& mb) {
            py::list ls(mb.modules.size()); size_t lssize = ls.size();
            for (size_t i = 0; i < lssize; i++) ls[i] = mb.modules[i];
            return ls;
        })
        .def_property("exeBuf", [](const MetaBlock& mb) {
                return py::bytes(
                    reinterpret_cast<const char*>(mb.exeBuf.data()),
                    mb.exeBuf.size()
                );
            },
        [](MetaBlock& mb, py::bytes bys){
                std::string tmp = bys;
                mb.exeBuf.assign(tmp.begin(), tmp.end());
            }
        );
}