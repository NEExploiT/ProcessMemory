# coding: utf-8
require 'spec_helper'

describe ProcessMemory do
  it 'has a version number' do
    expect(ProcessMemory::VERSION).not_to be nil
  end

  let(:mem){
    ProcessMemory::ProcessMemoryEx.new Process.pid
  }

  TESTSTRING = 'fake strings'
  TESTINT32 = 0xDEADBEEF
  TESTINT64 = 0xCAFEBABE15C001

  describe '#ptr_buf' do
    it 'read string' do
      test = Fiddle::Pointer[TESTSTRING]
      expect(
        mem.ptr_buf(test, test.size)
      ).to eq(TESTSTRING)
    end
  end

  describe '#ptr' do
    host_is_x64 = ProcessMemory::WinMemAPI::SIZEOF_PTR == 8 && 'ruby.exe is x64 version'
    host_is_x86 = ProcessMemory::WinMemAPI::SIZEOF_PTR == 4 && 'ruby.exe is x86 version'

    it 'read int32' do
      testp = Fiddle::Pointer[[TESTINT32].pack('q')]
      expect(mem.ptr(testp)).to eq(TESTINT32)
    end

    context 'when host(ruby.exe) is x64', skip: host_is_x86 do
      it 'read int64' do
        testp = Fiddle::Pointer[[TESTINT64].pack('q')]
        expect(mem.ptr(testp)).to eq(TESTINT64)
      end
    end
    context 'when host(ruby.exe) is x86', skip: host_is_x64 do
      it 'does not read int64' do
        testp = Fiddle::Pointer[[TESTINT64].pack('q')]
        expect(mem.ptr(testp)).to_not eq(TESTINT64)
      end
    end
  end # End of describe '#ptr'

  describe '#ptr_fmt' do
    it 'read single int64' do
      testp = Fiddle::Pointer[[TESTINT64].pack('q')]
      expect(mem.ptr_fmt(testp, 8, 'q')).to eq(TESTINT64)
    end
    it 'read multi int64' do
      test_data = [0xcafebabe, 0xC001Babe]
      testp = Fiddle::Pointer[test_data.pack('qq')]
      expect(mem.ptr_fmt(testp, testp.size, 'qq')).to eq(test_data)
    end
  end # End of describe '#ptr_fmt'

  describe '#strdup' do
    teststr = 'alphabet/日本語まじり表現の恐怖'
    it 'read utf8 string' do
      expect(mem.strdup(Fiddle::Pointer[teststr.encode(Encoding::UTF_8)])).to eq teststr
    end
    it 'read utf16 string' do
      expect(mem.strdup(Fiddle::Pointer[teststr.encode(Encoding::UTF_16)], atomic_size: 2)).to eq teststr
    end
    it 'read cp932 string' do
      expect(mem.strdup(Fiddle::Pointer[teststr.encode(Encoding::CP932)], encoding: Encoding::CP932)).to eq teststr
    end
    it 'read from cp932 to utf8' do
      expect(
        mem.strdup(Fiddle::Pointer[teststr.encode(Encoding::CP932)], encoding: Encoding::CP932).encoding
      ).to eq Encoding::UTF_8
    end
    it 'read from cp932 to utf16' do
      expect(
        mem.strdup(Fiddle::Pointer[teststr.encode(Encoding::CP932)],
                   encoding: Encoding::CP932, encode: Encoding::UTF_16).encoding
      ).to eq Encoding::UTF_16
    end
    it 'bad case, \0 into string' do
      badteststr = "alphabet日本語まじり\0表現の恐怖"
      expect(
        mem.strdup(Fiddle::Pointer[badteststr.encode(Encoding::UTF_8)])
      ).to_not eq badteststr
    end
  end

  describe ProcessMemory::ProcessMemoryUtil do
    before :all do
      ProcessMemory::ProcessMemoryEx.new Process.pid
    end
    describe '.ptr' do
      it 'read int32' do
        testp = Fiddle::Pointer[[TESTINT32].pack('q')]
        expect(ProcessMemory::ProcessMemoryUtil.ptr(testp)).to eq(TESTINT32)
      end
    end
  end
end # describe ProcessMemory
