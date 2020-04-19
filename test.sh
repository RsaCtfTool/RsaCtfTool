#!/bin/bash

cd "$(dirname "$0")"
clear
echo -e "\033[1mTest factordb expression parsing\033[0m"
./RsaCtfTool.py --publickey "examples/factordb_parse.pub" --private --attack factordb
echo -e "\033[1m\nTest noveltyprimes\033[0m"
./RsaCtfTool.py --publickey examples/elite_primes.pub --private --attack noveltyprimes
echo -e "\033[1m\nTest small_q\033[0m"
./RsaCtfTool.py --publickey examples/small_q.pub --private --uncipherfile examples/small_q.cipher --attack smallq
echo -e "\033[1m\nTest Mersenne Primes\033[0m"
./RsaCtfTool.py --private -e 0x10001 -n 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001 --attack mersenne_primes
echo -e "\033[1m\nTest wiener\033[0m"
./RsaCtfTool.py --publickey examples/wiener.pub --private --uncipherfile examples/wiener.cipher --attack wiener
echo -e "\033[1m\nTest Boneh Durfee\033[0m"
./RsaCtfTool.py --publickey examples/wiener.pub --private --uncipherfile examples/wiener.cipher --attack boneh_durfee
echo -e "\033[1m\nTest primefac\033[0m"
./RsaCtfTool.py --publickey examples/primefac.pub --private --attack primefac
echo -e "\033[1m\nTest commonfactors\033[0m"
./RsaCtfTool.py --publickey "examples/commonfactor?.pub" --private --attack commonfactors
echo -e "\033[1m\nTest fermat\033[0m"
./RsaCtfTool.py --publickey examples/close_primes.pub --private --uncipherfile examples/close_primes.cipher --attack fermat
echo -e "\033[1m\nTest fermat2\033[0m"
./RsaCtfTool.py --publickey examples/fermat.pub --private --attack fermat
echo -e "\033[1m\nTest pastctfprimes\033[0m"
./RsaCtfTool.py --publickey examples/pastctfprimes.pub --private --attack pastctfprimes
echo -e "\033[1m\nTest SIQS\033[0m"
./RsaCtfTool.py --publickey examples/siqs.pub --private --attack siqs
echo -e "\033[1m\nTest ECM\033[0m"
./RsaCtfTool.py --publickey examples/ecm_method.pub --private --ecmdigits 25 --attack ecm --timeout 60
echo -e "\033[1m\nTest createpub\033[0m"
./RsaCtfTool.py --createpub -n 8616460799 -e 65537
echo -e "\033[1m\nCreatepub into Crack feedback\033[0m"
./RsaCtfTool.py --createpub -n 163325259729739139586456854939342071588766536976661696628405612100543978684304953042431845499808366612030757037530278155957389217094639917994417350499882225626580260012564702898468467277918937337494297292631474713546289580689715170963879872522418640251986734692138838546500522994170062961577034037699354013013 -e 65537 > /tmp/crackme.txt
./RsaCtfTool.py --publickey /tmp/crackme.txt --private
rm -f /tmp/crackme.txt
echo -e "\033[1m\nTest hastads\033[0m"
./RsaCtfTool.py --publickey "examples/hastads01.pub,examples/hastads02.pub,examples/hastads03.pub" --uncipher 261345950255088824199206969589297492768083568554363001807292202086148198540785875067889853750126065910869378059825972054500409296763768604135988881188967875126819737816598484392562403375391722914907856816865871091726511596620751615512183772327351299941365151995536802718357319233050365556244882929796558270337,147535246350781145803699087910221608128508531245679654307942476916759248311896958780799558399204686458919290159543753966699893006016413718139713809296129796521671806205375133127498854375392596658549807278970596547851946732056260825231169253750741639904613590541946015782167836188510987545893121474698400398826,633230627388596886579908367739501184580838393691617645602928172655297372145912724695988151441728614868603479196153916968285656992175356066846340327304330216410957123875304589208458268694616526607064173015876523386638026821701609498528415875970074497028482884675279736968611005756588082906398954547838170886958 --attack hastads
echo -e "\033[1m\nTest informations output (--dumpkey --ext)\033[0m"
./RsaCtfTool.py --publickey "examples/factordb_parse.pub" --private --attack factordb --dumpkey --ext
echo -e "\033[1m\nTest unciphering multiple files\033[0m"
./RsaCtfTool.py --publickey examples/primefac.pub --uncipherfile examples/cipher1,examples/cipher2,examples/cipher3
echo -e "\033[1m\nTest unciphering single file with multiple keys\033[0m"
./RsaCtfTool.py --publickey examples/boneh_durfee.pub,examples/primefac.pub  --uncipherfile examples/cipher1