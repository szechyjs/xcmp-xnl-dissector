local proto = Proto("fxp", "Motorola FXP")

function proto.init()
  DissectorTable.get("udp.port"):add(4070, proto)
end

local randomizations = {
  [80] = "No random",
  [105] = "xKxK",
  [209] = "KxKx",
  [703] = "KxxKxx",
  [901] = "xxKxxK",
  [1403] = "KxxxKxxx",
  [10782] = "xxxKxxxK",
  [56016] = "128xK",
};

local proto_vers = {
  [1] = "AES256",
};

local operations = {
  [1] = "Discard",
  [2] = "Discard ACK",
  [3] = "Feature session request",
  [4] = "Feature session request ACK",
  [5] = "Feature code transfer",
  [6] = "Feature code transfer ACK",
  [7] = "Feature lock request",
  [8] = "Feature lock request ACK",
  [9] = "Feature unlock request",
  [10] = "Feature unlock request ACK",
};

proto.fields.length = ProtoField.uint16("fxp.length", "Length", base.DEC)
proto.fields.randomization = ProtoField.uint16("fxp.randomization", "Randomization", base.DEC, randomizations)
proto.fields.data = ProtoField.bytes("fxp.data", "Data")
proto.fields.proto = ProtoField.uint16("fxp.proto", "Protocol Version", base.DEC, proto_vers)
proto.fields.seq = ProtoField.uint16("fxp.seq", "Sequence Number", base.DEC)
proto.fields.op = ProtoField.uint16("fxp.op", "Operation", base.DEC, operations)

function derandomize(interval, start_with_k, data, start_index)
  local length = data:len() - start_index
  if length < 0 or length % (interval + 1) ~= 0 then
    return ""
  end

  local out_length = length / (interval + 1)
  local out_data = ""
  local num2 = start_with_k and start_index or (start_index + interval)
  for i = 0, out_length - 1 do
    local i2 = (interval + 1) * i + num2
    out_data = out_data .. data(i2, 1):raw(0, 1)
  end
  return out_data
end

function proto.dissector(buf, pkt, root)
  pkt.cols.protocol:set("FXP")

  local tree = root:add(proto, buf(0))

  tree:add(proto.fields.length, buf(0, 2))
  tree:add(proto.fields.randomization, buf(2, 2))

  local random_data = buf(4, buf(0,2):uint() - 2)
  local data_tree = tree:add(proto.fields.data, random_data)

  local data = ""
  local start_index = 0
  local randomization = buf(2, 2):uint()

  if randomization == 105 then
    -- xKxK
    data = derandomize(1, false, random_data, start_index)
  elseif randomization == 209 then
    -- KxKx
    data = derandomize(1, true, random_data, start_index)
  elseif randomization == 703 then
    -- KxxKxx
    data = derandomize(2, true, random_data, start_index)
  elseif randomization == 901 then
    -- xxKxxK
    data = derandomize(2, false, random_data, start_index)
  elseif randomization == 1403 then
    -- KxxxKxxx
    data = derandomize(3, true, random_data, start_index)
  elseif randomization == 10782 then
    -- xxxKxxxK
    data = derandomize(3, false, random_data, start_index)
  elseif randomization == 56016 then
    -- 128xK
    data = derandomize(0, true, random_data, start_index + 128)
  end

  local dec_data = ByteArray.new(data, true):tvb("Derandomized data")
  data_tree:add(proto.fields.data, dec_data())
  data_tree:add(proto.fields.proto, dec_data(0, 2))
  data_tree:add(proto.fields.seq, dec_data(2, 2))
end

