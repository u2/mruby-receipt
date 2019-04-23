module Ethereum
  module Constant

    BYTE_EMPTY = "".freeze
    BYTE_ZERO  = "\x00".freeze
    BYTE_ONE   = "\x01".freeze

    TT32   = 2**32
    TT40   = 2**40
    TT160  = 2**160
    TT256  = 2**256
    TT64M1 = 2**64 - 1

    UINT_MAX = 2**256 - 1
    UINT_MIN = 0
    INT_MAX  = 2**255 - 1
    INT_MIN  = -2**255

    HASH_ZERO = ("\x00"*32).freeze

    PUBKEY_ZERO = ("\x00"*32).freeze
    PRIVKEY_ZERO = ("\x00"*32).freeze
    PRIVKEY_ZERO_HEX = ('0'*64).freeze

    CONTRACT_CODE_SIZE_LIMIT = 0x6000

  end

  module Utils
    include Constant
    
    def keccak256(x)
      sha3 = Sha3.new
      sha3.update(x)
      sha3.final
    end

    def lpad(x, symbol, l)
      return x if x.size >= l
      symbol * (l - x.size) + x
    end

    def zpad(x, l)
      lpad x, BYTE_ZERO, l
    end

    def int_to_big_endian(n)
      RLP::Sedes.big_endian_int.serialize n
    end

    def encode_hex(b)
      RLP::Utils.encode_hex b
    end

    def decode_hex(s)
      RLP::Utils.decode_hex s
    end

    extend self
  end

  module Sedes
    include RLP::Sedes

    extend self

    def address
      Binary.fixed_length(20, allow_empty: true)
    end

    def int20
      BigEndianInt.new(20)
    end

    def int32
      BigEndianInt.new(32)
    end

    def int256
      BigEndianInt.new(256)
    end

    def hash32
      Binary.fixed_length(32)
    end

    def trie_root
      Binary.fixed_length(32, allow_empty: true)
    end

    def big_endian_int
      RLP::Sedes.big_endian_int
    end

    def binary
      RLP::Sedes.binary
    end

  end

  ###
  # Blooms are the 3-point, 2048-bit (11-bits/point) Bloom filter of each
  # component (except data) of each log entry of each transaction.
  #
  # We set the bits of a 2048-bit value whose indices are given by the low
  # order 9-bits of the first three double-bytes of the SHA3 of each value.
  #
  # @example
  #   bloom(0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6)
  #   sha3: bd2b01afcd27800b54d2179edc49e2bffde5078bb6d0b204694169b1643fb108
  #   first 3 double-bytes: bd2b, 01af, cd27
  #   bits in bloom: 1323, 431, 1319
  #
  # Blooms are type of `Integer`.
  #
  class Bloom

    BITS = 2048
    MASK = 2047
    BUCKETS = 3

    class <<self
      def from(v)
        insert(0, v)
      end

      def from_array(args)
        blooms = args.map {|arg| from(arg) }
        combine *blooms
      end

      def insert(bloom, v)
        h = Utils.keccak256 v
        BUCKETS.times {|i| bloom |= get_index(h, i) }
        bloom
      end

      def query(bloom, v)
        b = from v
        (bloom & b) == b
      end

      def combine(*args)
        args.reduce(0, &:|)
      end

      def bits(v)
        h = Utils.keccak256 v
        BUCKETS.times.map {|i| bits_in_number get_index(h, i) }
      end

      def bits_in_number(v)
        BITS.times.select {|i| (1<<i) & v > 0 }
      end

      def b256(int_bloom)
        Utils.zpad Utils.int_to_big_endian(int_bloom), 256
      end

      ##
      # Get index for hash double-byte in bloom.
      #
      # @param hash [String] value hash
      # @param pos [Integer] double-byte position in hash, can only be 0, 1, 2
      #
      # @return [Integer] bloom index
      #
      def get_index(hash, pos)
        raise ArgumentError, "invalid double-byte position" unless [0,1,2].include?(pos)

        i = pos*2
        hi = hash[i].ord << 8
        lo = hash[i+1].ord
        1 << ((hi+lo) & MASK)
      end

    end
  end

  class Log
    include RLP::Sedes::Serializable

    set_serializable_fields(
      address: Sedes.address,
      topics: RLP::Sedes::CountableList.new(Sedes.int32),
      data: Sedes.binary
    )

    def address
      @address
    end
  
    def address=(v)
      _set_field(:address, v)
    end

    def topics
      @topics
    end
  
    def topics=(v)
      _set_field(:topics, v)
    end

    def data
      @data
    end
  
    def data=(v)
      _set_field(:data, v)
    end

    def initialize(*args)
      h = parse_field_args args

      address = h[:address]
      raise ArgumentError, "invalid address: #{address}" unless address.size == 20 || address.size == 40

      address = Utils.decode_hex(address) if address.size == 40

      h[:address] = address
      super(h)
    end

    def bloomables
      topics.map {|t| Sedes.int32.serialize(t) }.unshift(address)
    end

    def to_h
      { bloom: Utils.encode_hex(Bloom.b256(Bloom.from_array(bloomables))),
        address: Utils.encode_hex(address),
        data: "0x#{Utils.encode_hex(data)}",
        topics: topics.map {|t| Utils.encode_hex(Sedes.int32.serialize(t)) }
      }
    end

    def to_s
      "#<#{self.class.name}:#{object_id} address=#{Utils.encode_hex(address)} topics=#{topics} data=#{data}>"
    end
    alias :inspect :to_s
  end

  class Receipt
    include RLP::Sedes::Serializable

    extend Sedes

    set_serializable_fields(
      # state_root: trie_root
      gas_used: big_endian_int,
      bloom: int256,
      logs: RLP::Sedes::CountableList.new(Log),
      error: RLP::Sedes::CountableList.new(Integer),
      account_nonce: big_endian_int,
      transaction_hash: hash32,
    )

    def gas_used
      @gas_used
    end
  
    def gas_used=(v)
      _set_field(:gas_used, v)
    end
  
    def bloom=(v)
      _set_field(:bloom, v)
    end

    def logs
      @logs
    end
  
    def logs=(v)
      _set_field(:logs, v)
    end

    def error
      @error
    end
  
    def error=(v)
      _set_field(:error, v)
    end

    def account_nonce
      @account_nonce
    end
  
    def account_nonce=(v)
      _set_field(:account_nonce, v)
    end

    def transaction_hash
      @transaction_hash
    end
  
    def transaction_hash=(v)
      _set_field(:transaction_hash, v)
    end

    # initialize(state_root, gas_used, logs, bloom: nil)
    def initialize(*args)
      h = normalize_args args
      super(h)

      raise ArgumentError, "Invalid bloom filter" if h[:bloom] && h[:bloom] != self.bloom
    end

    def bloom
      bloomables = logs.map {|l| l.bloomables }
      Bloom.from_array bloomables.flatten
    end

    private

    def normalize_args(args)
      options = args.last.is_a?(Hash) ? args.pop : {}
      field_set = %i(gas_used bloom logs error account_nonce transaction_hash) # different order than serializable fields

      h = {}
      fields = field_set[0,args.size]
      fields.zip(args).each do |field, arg|
        h[field] = arg
        field_set.delete field
      end

      options.each do |field, value|
        if field_set.include?(field)
          h[field] = value
          field_set.delete field
        end
      end

      field_set.each {|field| h[field] = nil }
      h
    end
  end
end
