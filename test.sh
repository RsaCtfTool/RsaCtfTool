#!/bin/bash

cd "$(dirname "$0")"

# Test factordb parsing notation where a prime is noted as an expression such as 2^1453-1
echo "Test factordb expression parsing"
./RsaCtfTool.py --publickey "examples/factordb_parse.pub" --verbose --private --attack factordb
# Test all the pub and ciphers
echo "Test multikey mode"
./RsaCtfTool.py --publickey "examples/multikey-?.pub" --verbose --private
echo "Test hastads"
./RsaCtfTool.py --publickey examples/small_exponent.pub --verbose --private --uncipherfile examples/small_exponent.cipher --attack hastads
echo "Test noveltyprimes"
./RsaCtfTool.py --publickey examples/elite_primes.pub --verbose --private
echo "Test small_q"
./RsaCtfTool.py --publickey examples/small_q.pub --verbose --private --uncipherfile examples/small_q.cipher
echo "Test wiener"
./RsaCtfTool.py --publickey examples/wiener.pub --verbose --private --uncipherfile examples/wiener.cipher --attack wiener
echo "Test commonfactors"
./RsaCtfTool.py --publickey examples/common_factor.pub --verbose --private --uncipherfile examples/common_factor.cipher
echo "Test fermat"
./RsaCtfTool.py --publickey examples/close_primes.pub --verbose --private --uncipherfile examples/close_primes.cipher
echo "Test fermat2"
./RsaCtfTool.py --publickey examples/fermat.pub --verbose --private
echo "Test pastctfprimes"
./RsaCtfTool.py --publickey examples/pastctfprimes.pub --verbose --private
echo "Test SIQS"
./RsaCtfTool.py --publickey examples/siqs.pub --verbose --private
echo "Test ECM"
./RsaCtfTool.py --publickey examples/ecm_method.pub --verbose --private --ecmdigits 25
echo "Test createpub"
./RsaCtfTool.py --createpub -n 8616460799 -e 65537
echo "Createpub into Crack feedback"
./RsaCtfTool.py --createpub -n 163325259729739139586456854939342071588766536976661696628405612100543978684304953042431845499808366612030757037530278155957389217094639917994417350499882225626580260012564702898468467277918937337494297292631474713546289580689715170963879872522418640251986734692138838546500522994170062961577034037699354013013 -e 65537 > /tmp/crackme.txt
./RsaCtfTool.py --publickey /tmp/crackme.txt --verbose --private
rm -f /tmp/crackme.txt
# Test smallfraction module
echo "Test smallfraction module"
./RsaCtfTool.py --publickey "examples/smallfraction.pub" --verbose --private
