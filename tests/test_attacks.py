#!/usr/bin/env python3

import subprocess
import sys
import tempfile
import os
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent


def _run(*args, timeout=60):
    cmd = [sys.executable, "-m", "RsaCtfTool"] + list(args)
    return subprocess.run(
        cmd, cwd=REPO_ROOT, capture_output=True, text=True, timeout=timeout
    )


class TestFactordbAttack:
    def test_factordb_attack_succeeds(self):
        result = _run(
            "--publickey",
            "examples/factordb_parse.pub",
            "--private",
            "--attack",
            "factordb",
        )
        assert result.returncode == 0

    @pytest.mark.network
    def test_factordb_no_ciphers(self):
        result = _run(
            "-n",
            "90377629292003121684002147101760858109247336549001090677693",
            "-e",
            "65537",
            "--sendtofdb",
            "--private",
            "--timeout",
            "100",
            "--attack",
            "factordb",
            timeout=160,
        )
        assert result.returncode == 0


class TestNoveltyPrimesAttack:
    def test_noveltyprimes_attack(self):
        result = _run(
            "--publickey",
            "examples/elite_primes.pub",
            "--private",
            "--attack",
            "noveltyprimes",
        )
        assert result.returncode == 0


class TestSmallQAttack:
    def test_smallq_attack_with_decrypt(self):
        result = _run(
            "--publickey",
            "examples/small_q.pub",
            "--private",
            "--decryptfile",
            "examples/small_q.cipher",
            "--attack",
            "smallq",
        )
        assert result.returncode == 0


class TestWienerAttack:
    def test_wiener_attack(self):
        result = _run(
            "--publickey",
            "examples/wiener.pub",
            "--private",
            "--decryptfile",
            "examples/wiener.cipher",
            "--attack",
            "wiener",
        )
        assert result.returncode == 0

    @pytest.mark.slow
    def test_boneh_durfee_attack(self):
        result = _run(
            "--publickey",
            "examples/wiener.pub",
            "--private",
            "--decryptfile",
            "examples/wiener.cipher",
            "--attack",
            "boneh_durfee",
            timeout=300,
        )
        assert result.returncode == 0


class TestCommonFactorsAttack:
    def test_commonfactors_attack(self):
        result = _run(
            "--publickey",
            "examples/commonfactor?.pub",
            "--private",
            "--attack",
            "common_factors",
        )
        assert result.returncode == 0


class TestCommonModulusRelatedMessageAttack:
    def test_common_modulus_related_message_attack(self):
        result = _run(
            "--publickey",
            "examples/common_modulus1.pub,examples/common_modulus2.pub",
            "--decrypt",
            "1925,2876",
            "--attack",
            "common_modulus_related_message",
            "--private",
        )
        assert result.returncode == 0
        assert "0x0c" in result.stderr


class TestFermatAttack:
    def test_fermat_attack_close_primes(self):
        result = _run(
            "--publickey",
            "examples/close_primes.pub",
            "--private",
            "--decryptfile",
            "examples/close_primes.cipher",
            "--attack",
            "fermat",
        )
        assert result.returncode == 0

    def test_fermat_attack_basic(self):
        result = _run(
            "--publickey", "examples/fermat.pub", "--private", "--attack", "fermat"
        )
        assert result.returncode == 0


class TestPastCTFPrimesAttack:
    def test_pastctfprimes_attack(self):
        result = _run(
            "--publickey",
            "examples/pastctfprimes.pub",
            "--private",
            "--attack",
            "pastctfprimes",
        )
        assert result.returncode == 0


class TestCreatePub:
    def test_createpub_basic(self):
        result = _run("--createpub", "-n", "8616460799", "-e", "65537")
        assert result.returncode == 0

    @pytest.mark.slow
    def test_createpub_and_crack(self):
        n = "163325259729739139586456854939342071588766536976661696628405612100543978684304953042431845499808366612030757037530278155957389217094639917994417350499882225626580260012564702898468467277918937337494297292631474713546289580689715170963879872522418640251986734692138838546500522994170062961577034037699354013013"
        with tempfile.NamedTemporaryFile(suffix=".pub", delete=False) as tmp:
            tmp_path = tmp.name
        try:
            create_result = _run("--createpub", "-n", n, "-e", "65537")
            assert create_result.returncode == 0
            Path(tmp_path).write_text(create_result.stdout)
            crack_result = _run(
                "--publickey", tmp_path, "--private", "--timeout", "120", timeout=180
            )
            assert crack_result.returncode == 0
        finally:
            os.unlink(tmp_path)


class TestHastadsAttack:
    def test_hastads_attack(self):
        ct = (
            "261345950255088824199206969589297492768083568554363001807292202086148198540785875067889853750126065910869378059825972054500409296763768604135988881188967875126819737816598484392562403375391722914907856816865871091726511596620751615512183772327351299941365151995536802718357319233050365556244882929796558270337,"
            "147535246350781145803699087910221608128508531245679654307942476916759248311896958780799558399204686458919290159543753966699893006016413718139713809296129796521671806205375133127498854375392596658549807278970596547851946732056260825231169253750741639904613590541946015782167836188510987545893121474698400398826,"
            "633230627388596886579908367739501184580838393691617645602928172655297372145912724695988151441728614868603479196153916968285656992175356066846340327304330216410957123875304589208458268694616526607064173015876523386638026821701609498528415875970074497028482884675279736968611005756588082906398954547838170886958"
        )
        result = _run(
            "--publickey",
            "examples/hastads01.pub,examples/hastads02.pub,examples/hastads03.pub",
            "--decrypt",
            ct,
            "--attack",
            "hastads",
        )
        assert result.returncode == 0


class TestECMAttack:
    @pytest.mark.slow
    def test_ecm_attack(self):
        result = _run(
            "--publickey",
            "examples/ecm_method.pub",
            "--private",
            "--ecmdigits",
            "25",
            "--attack",
            "ecm",
            "--timeout",
            "120",
            timeout=180,
        )
        assert result.returncode == 0


class TestSIQSAttack:
    @pytest.mark.slow
    def test_siqs_attack(self):
        result = _run(
            "--publickey",
            "examples/siqs.pub",
            "--private",
            "--attack",
            "siqs",
            timeout=300,
        )
        assert result.returncode == 0


class TestROCAAttack:
    @pytest.mark.slow
    def test_roca_attack(self):
        n = "5590772118685579117817112787486780348504267507289026685912623973671010394384988015497235515969796783937905129055952167826830196634107346761087047942625347"
        result = _run(
            "--attack",
            "roca",
            "-n",
            n,
            "-e",
            "65537",
            "--private",
            "--timeout",
            "90",
            timeout=150,
        )
        assert result.returncode == 0


class TestCubeRootAttack:
    def test_cube_root_attack(self):
        ct = "2205316413931134031074603746928247799030155221252519872650101242908540609117693035883827878696406295617513907962419726541451312273821810017858485722109359971259158071688912076249144203043097720816270550387459717116098817458584146690177125"
        n = "29331922499794985782735976045591164936683059380558950386560160105740343201513369939006307531165922708949619162698623675349030430859547825708994708321803705309459438099340427770580064400911431856656901982789948285309956111848686906152664473350940486507451771223435835260168971210087470894448460745593956840586530527915802541450092946574694809584880896601317519794442862977471129319781313161842056501715040555964011899589002863730868679527184420789010551475067862907739054966183120621407246398518098981106431219207697870293412176440482900183550467375190239898455201170831410460483829448603477361305838743852756938687673"
        result = _run("--decrypt", ct, "-e", "3", "-n", n, "--attack", "cube_root")
        assert result.returncode == 0


class TestDumpKey:
    @pytest.mark.slow
    def test_dumpkey_extended(self):
        result = _run(
            "--publickey",
            "examples/factordb_parse.pub",
            "--private",
            "--attack",
            "factordb",
            "--dumpkey",
            "--ext",
            "--timeout",
            "120",
            timeout=180,
        )
        assert result.returncode == 0


class TestDecryptFile:
    @pytest.mark.network
    @pytest.mark.slow
    def test_decrypt_multiple_files(self):
        result = _run(
            "--publickey",
            "examples/primefac.pub",
            "--decryptfile",
            "examples/cipher1,examples/cipher2,examples/cipher3",
            "--private",
            "--timeout",
            "120",
            timeout=300,
        )
        assert result.returncode == 0

    @pytest.mark.network
    def test_decrypt_multiple_keys(self):
        result = _run(
            "--publickey",
            "examples/boneh_durfee.pub,examples/primefac.pub",
            "--decryptfile",
            "examples/cipher1",
            "--private",
            "--timeout",
            "120",
            timeout=180,
        )
        assert result.returncode == 0


class TestGCDAttacks:
    def test_fermat_numbers_gcd(self):
        result = _run(
            "--publickey",
            "examples/fermat_numbers_gcd.pub",
            "--attack",
            "fermat_numbers_gcd",
            "--private",
        )
        assert result.returncode == 0

    def test_mersenne_pm1_gcd(self):
        result = _run(
            "--publickey",
            "examples/mersenne_pm1_gcd.pub",
            "--attack",
            "mersenne_pm1_gcd",
            "--private",
        )
        assert result.returncode == 0

    def test_primorial_pm1_gcd(self):
        result = _run(
            "--publickey",
            "examples/primorial_pm1_gcd.pub",
            "--attack",
            "primorial_pm1_gcd",
            "--private",
        )
        assert result.returncode == 0

    def test_fibonacci_gcd(self):
        result = _run(
            "--publickey",
            "examples/fibonacci_gcd.pub",
            "--attack",
            "fibonacci_gcd",
            "--private",
        )
        assert result.returncode == 0


class TestSmallCRTExpAttack:
    def test_small_crt_exp_attack(self):
        result = _run(
            "--publickey",
            "examples/small_crt_exp.pub",
            "--attack",
            "small_crt_exp",
            "--private",
        )
        assert result.returncode == 0


class TestSameNHugeEAttack:
    def test_same_n_huge_e_attack(self):
        n = "111381961169589927896512557754289420474877632607334685306667977794938824018345795836303161492076539375959731633270626091498843936401996648820451019811592594528673182109109991384472979198906744569181673282663323892346854520052840694924830064546269187849702880332522636682366270177489467478933966884097824069977"
        ct = (
            "54995751387258798791895413216172284653407054079765769704170763023830130981480272943338445245689293729308200574217959018462512790523622252479258419498858307898118907076773470253533344877959508766285730509067829684427375759345623701605997067135659404296663877453758701010726561824951602615501078818914410959610,"
            "91290935267458356541959327381220067466104890455391103989639822855753797805354139741959957951983943146108552762756444475545250343766798220348240377590112854890482375744876016191773471853704014735936608436210153669829454288199838827646402742554134017280213707222338496271289894681312606239512924842845268366950"
        )
        result = _run(
            "-e", "17,65537", "-n", n, "--decrypt", ct, "--attack", "same_n_huge_e"
        )
        assert result.returncode == 0


class TestRecoverPQFromNED:
    def test_recover_pq_from_ned(self):
        n = "89934323724424476294622381914221598261172812339375937399819972835334987445410253468222803336854810492858522510908818094465016971590866316799035894022707639444280657007098400914330738658538222266810030027839572053039403693393753168793586929250804215645550571352191199523184200836146013025928003383641371070393"
        d = "19962381665611835400733506106568527547878006333840452894627174646926439452040571847997880893864945423800493262831539082048043118936361632520188216585262183981035631032111326630882344091716101231068324973284629229989266282536689424414069614476142574917412326437716108488193134735278253062332252976826038348973"
        result = _run("--private", "-n", n, "-e", "65537", "-d", d)
        assert result.returncode == 0
