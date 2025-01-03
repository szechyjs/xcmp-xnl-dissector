local proto = Proto("xcmp", "Motorola XCMP")

local opcodes_base = {
  [0x0001] = "SOFTPOT",
  [0x0002] = "TRANSMITCFG",
  [0x0003] = "RECEIVECFG",
  [0x0004] = "TRANSMIT",
  [0x0005] = "RECEIVE",
  [0x0006] = "TXPWRLVL",
  [0x0007] = "EMPHASIS",
  [0x000a] = "RXFREQ",
  [0x000b] = "TXFREQ",
  [0x000c] = "TESTMODE",
  [0x000d] = "RESET",
  [0x000e] = "RSTATUS",
  [0x000f] = "VERINFO",
  [0x0010] = "RMODEL",
  [0x0011] = "SERIAL",
  [0x0012] = "UUID",
  [0x0016] = "RXBERCTRL",
  [0x0017] = "RXBERSYNC",
  [0x0023] = "DSCREMDEV",
  [0x0024] = "REMCONNECT",
  [0x0025] = "REMDISCONNECT",
  [0x002b] = "LANGPK",
  [0x002c] = "LANGPKINFO",
  [0x002e] = "SUPERBUNDLE",
  [0x0037] = "CPATTR",
  [0x003d] = "SECCONN",
  [0x0100] = "READISHITEM",
  [0x0101] = "WRITEISHITEM",
  [0x0102] = "DELISHIDS",
  [0x0103] = "DELISHTYPE",
  [0x0104] = "READISHIDSET",
  [0x0105] = "READISHTYPESET",
  [0x0106] = "ISHPGMMODE",
  [0x0107] = "ISHREORGCTRL",
  [0x0108] = "ISHUNLOCKPRT",
  [0x0109] = "CLONEWR",
  [0x010a] = "CLONERD",
  [0x010e] = "COMPREAD",
  [0x010f] = "COMPSESS",
  [0x0200] = "BOOTMODE",
  [0x0201] = "MEM",
  [0x0204] = "BOOTJMPEXEC",
  [0x0206] = "BOOTWRITECMT",
  [0x0207] = "REMDUP",
  [0x0208] = "FPGAOP",
  [0x0300] = "RKEY",
  [0x0301] = "UNLOCKSEC",
  [0x0400] = "DEVINITSTS",
  [0x0401] = "DISPTXT",
  [0x0402] = "INDUPDRQ",
  [0x0405] = "PUINPUT",
  [0x0406] = "VOLCTRL",
  [0x0407] = "SPKRCTRL",
  [0x0408] = "TXPWRLVL",
  [0x0409] = "TONECTRL",
  [0x040a] = "SHUTDWN",
  [0x040c] = "MON",
  [0x040d] = "CHZNSEL",
  [0x040e] = "MICCTRL",
  [0x040f] = "SCAN",
  [0x0410] = "BATLVL",
  [0x0411] = "BRIGHTNESS",
  [0x0412] = "BTNCONF",
  [0x0413] = "EMG",
  [0x0414] = "AUDRTCTRL",
  [0x0415] = "KEY",
  [0x041b] = "SIG",
  [0x041c] = "RRCTRL",
  [0x041d] = "DATA",
  [0x041e] = "CALLCTRL",
  [0x041f] = "NAVCTRL",
  [0x0420] = "MENUCTRL",
  [0x0421] = "DEVCTRL",
  [0x0428] = "DEVMGMT",
  [0x042e] = "ALARMCTRL",
  [0x042f] = "ROSCTRL",
  [0x0432] = "DATETIME",
  [0x0440] = "MEMSTRMREAD",
  [0x0441] = "MEMSTRMWRITE",
  [0x0443] = "NANDACCESS",
  [0x0444] = "FTLACCESS",
  [0x0445] = "FILEACCESS",
  [0x0447] = "RPTRCTRL",
  [0x0458] = "FD",
  [0x0461] = "MODINFO",
  [0x0467] = "CPPASSWDLCK",
  [0x046c] = "UNKILL",
  [0x04a1] = "SWA_AUDIO",
}

local opcodes = {}
for base, name in pairs(opcodes_base) do
  opcodes[base] = name .. "_REQ"
  opcodes[base + 0x8000] = name .. "_RES"
  opcodes[base + 0xb000] = name .. "_BRDCST"
end

local address_types = {
  [0] = "Local",
  [1] = "MotoTRBO",
  [2] = "IPv4",
  [5] = "MDC",
  [7] = "Phonenumber",
  [11] = "QuickCall",
  [13] = "5-Tone",
  [14] = "De-/Access Code",
}

local calltypes = {
  [0] = "No Call",
  [1] = "Selective Call",
  [2] = "Call Alert",
  [4] = "Enhanced Private Call",
  [5] = "Private Phone Call",
  [6] = "Group Call",
  [8] = "Call Alert with Voice",
  [9] = "Telegram Call",
  [10] = "Group Phone Call",
}

local results = {
  [0] = "Success",
  [2] = "Incorrect Mode",
  [3] = "Unsupported Opcode",
  [4] = "Invalid Parameter",
  [5] = "Reply Too Big",
  [6] = "Security Locked",
  [7] = "Unavailable Function",
}

local devinitsts_inits = {
  [0] = "STATUS",
  [1] = "COMPLETE",
  [2] = "UPDATE",
}

local devtypes = {
  [1] = "RF Transceiver",
  [10] = "IP Peripheral",
}

local devinitsts_attrs = {
  [0] = "Device Family",
  [2] = "Display",
  [3] = "Speaker",
  [4] = "RF Band",
  [5] = "GPIO",
  [7] = "Radio Type",
  [9] = "Keypad",
  [13] = "Channel Knob",
  [14] = "Virtual Personality",
  [17] = "Bluetooth",
  [19] = "Accelerometer",
  [20] = "GPS",
}

local rstatus_conds = {
  [0] = "Squelch",
  [1] = "Synthesizer lock detect",
  [2] = "RSSI",
  [3] = "Battery value",
  [4] = "Low battery",
  [5] = "Power up status",
  [6] = "Abacus tuning status",
  [7] = "Model number",
  [8] = "Serial number",
  [9] = "ESN",
  [10] = "IF input signal strength",
  [11] = "Product serial number",
  [12] = "Frequency offset",
  [13] = "Signaling mode",
  [14] = "Radio ID",
  [15] = "Radio alias",
  [16] = "Generic option board available",
  [17] = "Bandit wireline board available",
  [18] = "Alt image status of bandit controller FPGA",
  [19] = "Alt image status of bandit wireline FPGA",
  [20] = "Neptune feature status",
  [21] = "Meter status of bandit FPGA",
  [22] = "Select 5 radio ID",
  [23] = "Privacy type",
  [24] = "Bluetooth address",
  [25] = "Sideband suppression",
  [45] = "Radio update status",
  [75] = "Physical serial number",
  [77] = "Uptime", -- verify, not in code
  [78] = "Default gateway network attachment"
};

local verinfo_types = {
  [0] = "Host software version",
  [2] = "BBF bundle version",
  [16] = "DSP software version",
  [17] = "DSP compatibility",
  [19] = "DTP compatibility",
  [34] = "Mace flash version",
  [36] = "Mace hardware version",
  [37] = "Mace hardware type",
  [48] = "Flash boot app version",
  [50] = "Ramdownloader version",
  [53] = "L3 bootloader version",
  [64] = "Tune version",
  [65] = "Security version",
  [66] = "Codeplug version",
  [80] = "PSDT version",
  [81] = "Configuration version",
  [82] = "Kernel version",
  [109] = "Flash size",
  [130] = "Option board name",
  [132] = "Option board hardware type",
  [133] = "Option board main app version",
  [135] = "Option board flash image type",
  [136] = "Option board flash image version",
  [164] = "Consolette board HW type",
  [165] = "Consolette board host version",
  [176] = "FPGA controller alt version",
  [177] = "FPGA controller factory version",
  [178] = "FPGA controller active version",
  [179] = "FPGA wireline alt version",
  [180] = "FPGA wireline factory version",
  [181] = "FPGA wireline active version",
}

local serial_ops = {
  [0] = "Read",
  [1] = "Write",
};

local model_ops = {
  [0] = "Read",
  [1] = "Write",
};

local cpattr_ops = {
  [1] = "Read",
  [2] = "Write",
};

local cpattrs = {
  [0] = "None",
  [1] = "Total allowable memory",
  [2] = "Current memory used",
  [3] = "Regional information",
  [4] = "OEM manufacurer ID",
  [7] = "Radio security information",
  [9] = "Certificate supported ID",
};

local langpk_ops = {
  [0] = "Single",
  [1] = "All",
  [2] = "Default",
  [3] = "ALL TTS",
};

local passwd_lock_fns = {
  [0] = "Request status",
  [1] = "Verify password",
  [2] = "Pair device",
  [3] = "Unpair device",
  [4] = "Verify pair",
};

local f_opcode = ProtoField.uint16("xcmp.opcode", "Opcode", base.HEX, opcodes)
local f_result = ProtoField.uint8("xcmp.result", "Result", base.DEC, results)
local f_address_type = ProtoField.uint8("xcmp.address.type", "Type", base.DEC, address_types)
local f_address_mototrbo = ProtoField.bytes("xcmp.address.mototrbo", "MotoTRBO ID")
local f_rstatus_cond = ProtoField.uint8("xcmp.rstatus.cond", "Condition", base.DEC, rstatus_conds)
local f_rstatus_status = ProtoField.bytes("xcmp.rstatus.status", "Status")
local f_devinitsts_major = ProtoField.uint8("xcmp.devinitsts.major", "Major Version", base.DEC)
local f_devinitsts_minor = ProtoField.uint8("xcmp.devinitsts.minor", "Minor Version", base.DEC)
local f_devinitsts_patch = ProtoField.uint8("xcmp.devinitsts.patch", "Patch Version", base.DEC)
local f_devinitsts_product = ProtoField.uint8("xcmp.devinitsts.product", "Product ID", base.DEC)
local f_devinitsts_init = ProtoField.uint8("xcmp.devinitsts.init", "Initialization", base.DEC, devinitsts_inits)
local f_devinitsts_type = ProtoField.uint8("xcmp.devinitsts.type", "Type", base.DEC, devtypes)
local f_devinitsts_status = ProtoField.uint16("xcmp.devinitsts.status", "Status", base.DEC)
local f_devinitsts_attrlen = ProtoField.uint8("xcmp.devinitsts.status", "Attribute Length", base.DEC)
local f_devinitsts_attr = ProtoField.bytes("xcmp.devinitsts.attr", "Attribute")
local f_devinitsts_attr_key = ProtoField.uint8("xcmp.devinitsts.attr.key", "Key", base.HEX, devinitsts_attrs)
local f_devinitsts_attr_value = ProtoField.uint8("xcmp.devinitsts.attr.value", "Value", base.HEX)
local f_rrctrl_feature = ProtoField.uint8("xcmp.rrctrl.feature", "Feature", base.DEC)
local f_rrctrl_operation = ProtoField.uint8("xcmp.rrctrl.operation", "Operation", base.DEC)
local f_rrctrl_status = ProtoField.uint8("xcmp.rrctrl.status", "Status", base.DEC)
local f_rrctrl_address = ProtoField.bytes("xcmp.rrctrl.address", "Address")
local f_chznsel_function = ProtoField.uint8("xcmp.chznsel.function", "Function", base.DEC)
local f_chznsel_zone = ProtoField.uint16("xcmp.chznsel.zone", "Zone", base.DEC)
local f_chznsel_position = ProtoField.uint16("xcmp.chznsel.position", "Position", base.DEC)
local f_scan_function = ProtoField.uint8("xcmp.scan.function", "Function", base.DEC)
local f_callctrl_function = ProtoField.uint8("xcmp.callctrl.function", "Function", base.DEC)
local f_callctrl_calltype = ProtoField.uint8("xcmp.callctrl.calltype", "Call Type", base.DEC, calltypes)
local f_callctrl_address = ProtoField.bytes("xcmp.callctrl.address", "Address")
local f_callctrl_group = ProtoField.bytes("xcmp.callctrl.group", "Group ID")
local f_verinfo_type = ProtoField.uint8("xcmp.verinfo.type", "Version Type", base.DEC, verinfo_types)
local f_verinfo_value = ProtoField.stringz("xcmp.verinfo.value", "Version")
local f_rmodel_op = ProtoField.uint8("xcmp.rmodel.op", "Model Operation", base.DEC, model_ops)
local f_rmodel_value = ProtoField.stringz("xcmp.rmodel.value", "Model")
local f_serial_op = ProtoField.uint8("xcmp.serial.op", "Serial Number Operation", base.DEC, serial_ops)
local f_serial_value = ProtoField.stringz("xcmp.serial.value", "Serial Number")
local f_cpattr_op = ProtoField.uint8("xcmp.cpattr.op", "Codeplug Attribute Operation", base.DEC, cpattr_ops)
local f_cpattr = ProtoField.uint8("xcmp.cpattr.attr", "Codeplug Attribute", base.DEC, cpattrs)
local f_cpattr_len = ProtoField.uint8("xcmp.cpattr.op", "Codeplug Attribute Length", base.DEC)
local f_cpattr_value = ProtoField.bytes("xcmp.cpattr.value", "Codeplug Attribute Value")
local f_readish_lp = ProtoField.uint8("xcmp.readish.lp", "ISH Logical Partition", base.DEC)
local f_readish_type = ProtoField.uint16("xcmp.readish.type", "ISH Type", base.DEC)
local f_readish_id = ProtoField.uint16("xcmp.readish.id", "ISH ID", base.DEC)
local f_readish_len = ProtoField.uint16("xcmp.readish.len", "ISH Number of Bytes", base.DEC)
local f_readish_offset = ProtoField.uint16("xcmp.readish.offset", "ISH Offset", base.DEC)
local f_readish_itmsz = ProtoField.uint16("xcmp.readish.itmsz", "ISH Item Size", base.DEC)
local f_readish_ids = ProtoField.uint16("xcmp.readish.ids", "ISH Number of IDs", base.DEC)
local f_readish_tot_ids = ProtoField.uint16("xcmp.readish.totids", "ISH Total ID Count", base.DEC)
local f_readish_data = ProtoField.bytes("xcmp.readish.data", "ISH Item Data")
local f_uuid = ProtoField.bytes("xcmp.uuid", "UUID")
local f_langpk = ProtoField.bytes("xcmp.langpk", "Language Pack")
local f_langpk_op = ProtoField.uint8("xcmp.langpk.op", "Language Pack Operation", base.DEC, langpk_ops)
local f_langpk_id = ProtoField.string("xcmp.langpk.id", "Language Pack ID")
local f_langpk_maj = ProtoField.uint32("xcmp.langpk.major", "Language Pack Major Version", base.DEC)
local f_langpk_min = ProtoField.uint32("xcmp.langpk.minor", "Language Pack Minor Version", base.DEC)
local f_langpk_siz = ProtoField.uint32("xcmp.langpk.size", "Language Pack Size", base.DEC)
local f_langpk_avail = ProtoField.uint32("xcmp.langpk.avail", "Language Pack Available Space", base.DEC)
local f_langpk_cap = ProtoField.uint8("xcmp.langpk.cap", "Language Pack Capacity", base.DEC)
local f_langpk_name = ProtoField.string("xcmp.langpk.name", "Language Pack Name")
local f_pwdlck_fn = ProtoField.uint8("xcmp.pwdlck.fn", "Password Lock Function", base.DEC, passwd_lock_fns)
local f_pwdlck_pol = ProtoField.uint8("xcmp.pwdlck.pol", "Password Lock Policy", base.DEC)
local f_pwdlck_alg = ProtoField.uint32("xcmp.pwdlck.alg", "Password Lock Algorithm", base.DEC)

proto.fields = {
  f_opcode,
  f_address_type,
  f_address_mototrbo,
  f_result,
  f_rstatus_cond,
  f_rstatus_status,
  f_devinitsts_major,
  f_devinitsts_minor,
  f_devinitsts_patch,
  f_devinitsts_product,
  f_devinitsts_init,
  f_devinitsts_type,
  f_devinitsts_status,
  f_devinitsts_attrlen,
  f_devinitsts_attr,
  f_devinitsts_attr_key,
  f_devinitsts_attr_value,
  f_rrctrl_feature,
  f_rrctrl_operation,
  f_rrctrl_status,
  f_rrctrl_address,
  f_chznsel_function,
  f_chznsel_zone,
  f_chznsel_position,
  f_scan_function,
  f_callctrl_function,
  f_callctrl_calltype,
  f_callctrl_address,
  f_callctrl_group,
  f_verinfo_type,
  f_verinfo_value,
  f_rmodel_op,
  f_rmodel_value,
  f_serial_op,
  f_serial_value,
  f_cpattr_op,
  f_cpattr_value,
  f_cpattr_len,
  f_cpattr,
  f_readish_lp,
  f_readish_type,
  f_readish_id,
  f_readish_len,
  f_readish_offset,
  f_readish_itmsz,
  f_readish_data,
  f_readish_ids,
  f_readish_tot_ids,
  f_uuid,
  f_langpk,
  f_langpk_op,
  f_langpk_id,
  f_langpk_maj,
  f_langpk_min,
  f_langpk_siz,
  f_langpk_name,
  f_langpk_avail,
  f_langpk_cap,
  f_pwdlck_fn,
  f_pwdlck_pol,
  f_pwdlck_alg,
}

-- dofile("xnl.luainc") -- uncomment to fix dependency order
local xnl_opcode = Field.new("xnl.opcode")
local xnl_transaction = Field.new("xnl.transaction")

function dissect_address(root, field, buf)
  local type = buf(0, 1):uint()
  local size = buf(1, 1):uint()
  local tree = root:add(field, buf(0, 2 + size))
  tree:add(f_address_type, buf(0, 1))
  if type == 1 then
    tree:add(f_address_mototrbo, buf(2, size))
  end
  return buf(2 + size)
end

function proto.init()
  DissectorTable.get("xnl.proto"):add(1, proto)
end

function proto.dissector(buf, pkt, root)
  if xnl_opcode().value == 12 and buf:len() == 0 then
    return
  end

  local tree = root:add(proto, buf(0, buf:len()))
  local opcode = buf(0, 2):uint()
  tree:add(f_opcode, buf(0, 2))

  local desc = (opcodes[opcode] or opcode) .. " Transaction=" .. xnl_transaction().value

  local result = nil
  if (opcode >> 12) == 8 then
    result = buf(2, 1):uint()
    tree:add(f_result, buf(2, 1))
  end

  if opcode == 0x000e then
    tree:add(f_rstatus_cond, buf(2, 1))
    desc = desc .. " Cond=" .. buf(2, 1):uint()
  elseif opcode == 0x800e then
    if result == 0 then
      tree:add(f_rstatus_cond, buf(3, 1))
      tree:add(f_rstatus_status, buf(4, buf:len() - 4))
      desc = desc .. " Cond=" .. buf(3, 1):uint()
    end
  elseif opcode == 0x000f then
    tree:add(f_verinfo_type, buf(2, 1))
    desc = desc .. " Type=" .. buf(2, 1):uint()
  elseif opcode == 0x800f then
    tree:add(f_verinfo_value, buf(3, buf:len() - 3))
  elseif opcode == 0x0010 then
    tree:add(f_rmodel_op, buf(2, 1))
    desc = desc .. " Op=" .. buf(2, 1):uint()
  elseif opcode == 0x8010 then
    tree:add(f_rmodel_value, buf(3, buf:len() - 3))
  elseif opcode == 0x0011 then
    tree:add(f_serial_op, buf(2, 1))
    desc = desc .. " Op=" .. buf(2, 1):uint()
  elseif opcode == 0x8011 then
    tree:add(f_serial_value, buf(3, buf:len() - 3))
  elseif opcode == 0x8012 then
    tree:add(f_uuid, buf(3, 16))
  elseif opcode == 0x002c then
    tree:add(f_langpk_op, buf(2, 1))
    desc = desc .. " Op=" .. buf(2, 1):uint()
  elseif opcode == 0x802c then
    local offset = 3
    tree:add(f_langpk_avail, buf(offset, 4))
    offset = offset + 4
    local cap = buf(offset, 1)
    offset = offset + 1
    tree:add(f_langpk_cap, cap)
    for i = 0, cap:uint() - 1 do
      local len = buf(offset,1):uint()
      local pack = tree:add(f_langpk, buf(offset, len))
      offset = offset + 1
      local getId = buf(offset, 16)
      local id = getId:ustring()
      offset = offset + 16
      pack:add(f_langpk_id, getId, id)
      pack:add(f_langpk_maj, buf(offset, 4))
      offset = offset + 4
      pack:add(f_langpk_min, buf(offset, 4))
      offset = offset + 4
      pack:add(f_langpk_siz, buf(offset, 4))
      offset = offset + 4
      local nameLen = len - 29
      local getName = buf(offset, nameLen)
      local name = getName:ustring()
      offset = offset + nameLen
      pack:add(f_langpk_name, getName, name)
    end
  elseif opcode == 0x0037 then
    tree:add(f_cpattr_op, buf(2, 1))
    tree:add(f_cpattr, buf(3, 1))
    tree:add(f_cpattr_len, buf(4, 1))
    desc = desc .. " Op=" .. buf(2, 1):uint() .. " Attr=" .. buf(3, 1):uint()
  elseif opcode == 0x8037 then
    tree:add(f_cpattr_op, buf(3, 1))
    tree:add(f_cpattr, buf(4, 1))
    local attr_len = buf(5, 1)
    tree:add(f_cpattr_len, attr_len)
    tree:add(f_cpattr_value, buf(6, attr_len:uint()))
    desc = desc .. " Op=" .. buf(3, 1):uint() .. " Attr=" .. buf(4, 1):uint()
  elseif opcode == 0x0100 then
    local lp = buf(2, 1)
    local type = buf(3, 2)
    local id = buf(5, 2)
    tree:add(f_readish_lp, lp)
    tree:add(f_readish_type, type)
    tree:add(f_readish_id, id)
    tree:add(f_readish_len, buf(7, 2))
    tree:add(f_readish_offset, buf(9, 2))
    desc = desc .. " LP=" .. lp:uint() .. " Type=" .. type:uint() .. " ID=" .. id:uint()
  elseif opcode == 0x8100 then
    local lp = buf(3, 1)
    local type = buf(4, 2)
    local id = buf(6, 2)
    tree:add(f_readish_lp, lp)
    tree:add(f_readish_type, type)
    tree:add(f_readish_id, id)
    local len = buf(8, 2):uint()
    tree:add(f_readish_len, len)
    tree:add(f_readish_offset, buf(10, 2))
    tree:add(f_readish_itmsz, buf(12, 2))
    tree:add(f_readish_data, buf(14, len))
    desc = desc .. " LP=" .. lp:uint() .. " Type=" .. type:uint() .. " ID=" .. id:uint()
  elseif opcode == 0x0104 then
    local lp = buf(2, 1)
    local type = buf(3, 2)
    local num_ids = buf(5, 2)
    tree:add(f_readish_lp, lp)
    tree:add(f_readish_type, type)
    tree:add(f_readish_ids, num_ids)
    tree:add(f_readish_offset, buf(7, 2))
    desc = desc .. " LP=" .. lp:uint() .. " Type=" .. type:uint() .. " IDs=" .. num_ids:uint()
  elseif opcode == 0x8104 then
    local lp = buf(3, 1)
    local type = buf(4, 2)
    local num_ids = buf(6, 2)
    tree:add(f_readish_lp, lp)
    tree:add(f_readish_type, type)
    tree:add(f_readish_ids, num_ids)
    tree:add(f_readish_offset, buf(8, 2))
    tree:add(f_readish_tot_ids, buf(10, 2))
    tree:add(f_readish_data, buf(12, num_ids:uint() * 2)) -- TODO: make array of uint16 ids
    desc = desc .. " LP=" .. lp:uint() .. " Type=" .. type:uint() .. " IDs=" .. num_ids:uint()
  elseif opcode == 0xb400 then
    tree:add(f_devinitsts_major, buf(2, 1))
    tree:add(f_devinitsts_minor, buf(3, 1))
    tree:add(f_devinitsts_patch, buf(4, 1))
    tree:add(f_devinitsts_product, buf(5, 1))
    local devinitsts_init = buf(6, 1):uint()
    tree:add(f_devinitsts_init, buf(6, 1))
    desc = desc .. " Init=" .. (devinitsts_inits[devinitsts_init] or devinitsts_init)
    if devinitsts_init ~= 1 then
      tree:add(f_devinitsts_type, buf(7, 1))
      tree:add(f_devinitsts_status, buf(8, 2))
      local attrlen = buf(10, 1):uint()
      tree:add(f_devinitsts_attrlen, buf(10, 1))
      for i = 0, (attrlen - 1), 2 do
        local attr_tree = tree:add(f_devinitsts_attr, buf(11 + i, 2))
        local attr_key = buf(11 + i, 1):uint()
        attr_tree:add(f_devinitsts_attr_key, buf(11 + i, 1))
        local attr_value = buf(11 + i + 1, 1):uint()
        attr_tree:add(f_devinitsts_attr_value, buf(11 + i + 1, 1))
        if devinitsts_attrs[attr_key] then
          attr_tree:set_text(string.format("%s: 0x%02x", devinitsts_attrs[attr_key], attr_value))
        end
      end
    end
  elseif opcode == 0x041c or opcode == 0xb41c then
    tree:add(f_rrctrl_feature, buf(2, 1))
    tree:add(opcode == 0x041c and f_rrctrl_operation or f_rrctrl_status, buf(3, 1))
    buf = dissect_address(tree, f_rrctrl_address, buf(4))
  elseif opcode == 0x040d then
    tree:add(f_chznsel_function, buf(2, 1))
    tree:add(f_chznsel_zone, buf(3, 2))
    tree:add(f_chznsel_position, buf(5, 2))
  elseif opcode == 0x040f then
    tree:add(f_scan_function, buf(2, 1))
  elseif opcode == 0x041e then
    tree:add(f_callctrl_function, buf(2, 1))
    tree:add(f_callctrl_calltype, buf(3, 1))
    buf = dissect_address(tree, f_callctrl_address, buf(4))
    if buf:len() > 0 then
      tree:add(f_callctrl_group, buf)
    end
  elseif opcode == 0x0467 then
    tree:add(f_pwdlck_fn, buf(2, 1))
    desc = desc .. " Fn=" .. buf(2, 1):uint()
  elseif opcode == 0x8467 then
    local fn = buf(2, 1)
    tree:add(f_pwdlck_fn, fn)
    if fn:uint() == 0 then
      tree:add(f_pwdlck_pol, buf(3, 1))
      tree:add(f_pwdlck_alg, buf(4, 4))
    elseif fn:uint() == 1 then
    elseif fn:uint() == 2 then
    elseif fn:uint() == 3 then
    end
    desc = desc .. " Fn=" .. buf(2, 1):uint()
  end

  pkt.cols.protocol:set("XCMP")
  pkt.cols.info:set(desc)
end
