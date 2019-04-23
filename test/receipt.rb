include RLP
include Ethereum

assert("test_receipt") do
  # gas_used bloom logs error account_nonce transaction_hash
  tx_hash = [230, 107, 198, 169, 247, 41, 26, 84, 177, 116, 141, 37, 138, 67, 87, 105, 216, 205, 120, 4, 144, 233, 212, 211, 21, 93, 140, 198, 158, 211, 171, 230].pack("C*")
  r = Receipt.new 0x134e33, "638668899051110339730039268171788341141584403339346413280815117579907805398068501051186548957643424348607405023804185178143997232870716734424399149307585741731226786117391460107520966903234877817657556188639377199637712499196056277262306490584048588682449033890972022537689917428690218781769728".to_big, [Log::new(address: "00000000000000000001", topics: [], data: "")], [], 1, tx_hash
  assert_equal 1265203, r.gas_used

  r_s = Receipt.serialize r

  # deserialization
  dr = Receipt.deserialize r_s, {}

  assert_equal r, dr

  data = RLP.encode(r)

  x = RLP.decode(data, { sedes: Receipt })

  assert_equal r, x
end