#!/usr/bin/env python3
"""
pytest equivalents of the attacks tested in test.sh.

Slow/network-dependent tests are decorated with @pytest.mark.slow so they
can be skipped with:  pytest -m "not slow"
"""

import subprocess
import sys
import tempfile
import os
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent


def _run(*args, timeout=60):
    """Run RsaCtfTool via `python -m RsaCtfTool` and return the CompletedProcess."""
    cmd = [sys.executable, "-m", "RsaCtfTool"] + list(args)
    return subprocess.run(
        cmd, cwd=REPO_ROOT, capture_output=True, text=True, timeout=timeout
    )


# ---------------------------------------------------------------------------
# Fast attacks (no @pytest.mark.slow)
# ---------------------------------------------------------------------------


def test_factordb():
    result = _run(
        "--publickey",
        "examples/factordb_parse.pub",
        "--private",
        "--attack",
        "factordb",
    )
    assert result.returncode == 0


def test_noveltyprimes():
    result = _run(
        "--publickey",
        "examples/elite_primes.pub",
        "--private",
        "--attack",
        "noveltyprimes",
    )
    assert result.returncode == 0


def test_smallq():
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


def test_mersenne_primes():
    # Exact value from test.sh line 12
    n = "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001"
    result = _run(
        "--private",
        "-e",
        "0x10001",
        "-n",
        n,
        "--attack",
        "mersenne_primes",
        timeout=120,
    )
    assert result.returncode == 0


def test_wiener():
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
def test_boneh_durfee():
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


def test_commonfactors():
    result = _run(
        "--publickey",
        "examples/commonfactor?.pub",
        "--private",
        "--attack",
        "commonfactors",
    )
    assert result.returncode == 0


def test_fermat():
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


def test_fermat2():
    result = _run(
        "--publickey", "examples/fermat.pub", "--private", "--attack", "fermat"
    )
    assert result.returncode == 0


def test_pastctfprimes():
    result = _run(
        "--publickey",
        "examples/pastctfprimes.pub",
        "--private",
        "--attack",
        "pastctfprimes",
    )
    assert result.returncode == 0


@pytest.mark.slow
def test_siqs():
    result = _run(
        "--publickey", "examples/siqs.pub", "--private", "--attack", "siqs", timeout=300
    )
    assert result.returncode == 0


@pytest.mark.slow
def test_ecm():
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


@pytest.mark.slow
def test_ecm2():
    n = "14641034851154010900546719241402474912998133209474218975103977449764205791710698412984067810848509509669017831054155506105922179074286929418416328797379636196613023210067141695123691351917498467761961980966631958692894027223505926821780581042313171803091956255639968110368314924456998367348008686435826036480738828760312467761150839006456972383"
    ct = "7102577393434866594929140550804968099111271800384955683330956013020579564684516163830573468073604865935034522944441894535695787080676107364035121171758895218132464499398807752144702697548021940878072503062685829101838944413876346837812265739970980202827485238414586892442822429233004808821082551675699702413952211939387589361654209039260795229"
    result = _run(
        "-n",
        n,
        "-e",
        "65537",
        "--decrypt",
        ct,
        "--attack",
        "ecm2",
        "--timeout",
        "60",
        timeout=120,
    )
    assert result.returncode == 0


def test_createpub():
    result = _run("--createpub", "-n", "8616460799", "-e", "65537")
    assert result.returncode == 0


def test_createpub_crack():
    n = "163325259729739139586456854939342071588766536976661696628405612100543978684304953042431845499808366612030757037530278155957389217094639917994417350499882225626580260012564702898468467277918937337494297292631474713546289580689715170963879872522418640251986734692138838546500522994170062961577034037699354013013"
    with tempfile.NamedTemporaryFile(suffix=".pub", delete=False) as tmp:
        tmp_path = tmp.name
    try:
        create_result = _run("--createpub", "-n", n, "-e", "65537")
        assert create_result.returncode == 0
        assert create_result.stdout.strip(), (
            "--createpub produced no output.\nSTDERR:\n%s" % create_result.stderr
        )
        Path(tmp_path).write_text(create_result.stdout)
        crack_result = _run("--publickey", tmp_path, "--private")
        assert crack_result.returncode == 0
    finally:
        os.unlink(tmp_path)


def test_hastads():
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


@pytest.mark.slow
def test_roca():
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


def test_dumpkey_ext():
    result = _run(
        "--publickey",
        "examples/factordb_parse.pub",
        "--private",
        "--attack",
        "factordb",
        "--dumpkey",
        "--ext",
    )
    assert result.returncode == 0


def test_decrypt_multiple_files():
    result = _run(
        "--publickey",
        "examples/primefac.pub",
        "--decryptfile",
        "examples/cipher1,examples/cipher2,examples/cipher3",
    )
    assert result.returncode == 0


def test_decrypt_multiple_keys():
    result = _run(
        "--publickey",
        "examples/boneh_durfee.pub,examples/primefac.pub",
        "--decryptfile",
        "examples/cipher1",
    )
    assert result.returncode == 0


def test_cube_root():
    ct = "2205316413931134031074603746928247799030155221252519872650101242908540609117693035883827878696406295617513907962419726541451312273821810017858485722109359971259158071688912076249144203043097720816270550387459717116098817458584146690177125"
    n = "29331922499794985782735976045591164936683059380558950386560160105740343201513369939006307531165922708949619162698623675349030430859547825708994708321803705309459438099340427770580064400911431856656901982789948285309956111848686906152664473350940486507451771223435835260168971210087470894448460745593956840586530527915802541450092946574694809584880896601317519794442862977471129319781313161842056501715040555964011899589002863730868679527184420789010551475067862907739054966183120621407246398518098981106431219207697870293412176440482900183550467375190239898455201170831410460483829448603477361305838743852756938687673"
    result = _run("--decrypt", ct, "-e", "3", "-n", n, "--attack", "cube_root")
    assert result.returncode == 0


def test_ekoparty():
    n = "79832181757332818552764610761349592984614744432279135328398999801627880283610900361281249973175805069916210179560506497075132524902086881120372213626641879468491936860976686933630869673826972619938321951599146744807653301076026577949579618331502776303983485566046485431039541708467141408260220098592761245010678592347501894176269580510459729633673468068467144199744563731826362102608811033400887813754780282628099443490170016087838606998017490456601315802448567772411623826281747245660954245413781519794295336197555688543537992197142258053220453757666537840276416475602759374950715283890232230741542737319569819793988431443"
    result = _run("--private", "-e", "65537", "-n", n)
    assert result.returncode == 0


def test_multiprime_nahamcon():
    n = "7735208939848985079680614633581782274371148157293352904905313315409418467322726702848189532721490121708517697848255948254656192793679424796954743649810878292688507385952920229483776389922650388739975072587660866986603080986980359219525111589659191172937047869008331982383695605801970189336227832715706317"
    ct = "5300731709583714451062905238531972160518525080858095184581839366680022995297863013911612079520115435945472004626222058696229239285358638047675780769773922795279074074633888720787195549544835291528116093909456225670152733191556650639553906195856979794273349598903501654956482056938935258794217285615471681"
    result = _run("-n", n, "-e", "65537", "--decrypt", ct, "--attack", "factordb")
    assert result.returncode == 0


def test_cm_factor():
    result = _run(
        "--publickey", "examples/cm_factor.pub", "--attack", "cm_factor", "--private"
    )
    assert result.returncode == 0


@pytest.mark.slow
def test_pollard_rho():
    result = _run(
        "--pub",
        "examples/pollard_rho.pub",
        "--attack",
        "pollard_rho",
        "--private",
        "--timeout",
        "180",
        timeout=240,
    )
    assert result.returncode == 0


def test_fermat_numbers_gcd():
    result = _run(
        "--publickey",
        "examples/fermat_numbers_gcd.pub",
        "--attack",
        "fermat_numbers_gcd",
        "--private",
    )
    assert result.returncode == 0


def test_mersenne_pm1_gcd():
    result = _run(
        "--publickey",
        "examples/mersenne_pm1_gcd.pub",
        "--attack",
        "mersenne_pm1_gcd",
        "--private",
    )
    assert result.returncode == 0


def test_primorial_pm1():
    result = _run(
        "--publickey",
        "examples/primorial_pm1_gcd.pub",
        "--attack",
        "primorial_pm1_gcd",
        "--private",
    )
    assert result.returncode == 0


def test_fibonacci_gcd():
    result = _run(
        "--publickey",
        "examples/fibonacci_gcd.pub",
        "--attack",
        "fibonacci_gcd",
        "--private",
    )
    assert result.returncode == 0


def test_small_crt_exp():
    result = _run(
        "--publickey",
        "examples/small_crt_exp.pub",
        "--attack",
        "small_crt_exp",
        "--private",
    )
    assert result.returncode == 0


@pytest.mark.slow
def test_factordb_no_ciphers():
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


def test_same_n_huge_e():
    n = "111381961169589927896512557754289420474877632607334685306667977794938824018345795836303161492076539375959731633270626091498843936401996648820451019811592594528673182109109991384472979198906744569181673282663323892346854520052840694924830064546269187849702880332522636682366270177489467478933966884097824069977"
    ct = (
        "54995751387258798791895413216172284653407054079765769704170763023830130981480272943338445245689293729308200574217959018462512790523622252479258419498858307898118907076773470253533344877959508766285730509067829684427375759345623701605997067135659404296663877453758701010726561824951602615501078818914410959610,"
        "91290935267458356541959327381220067466104890455391103989639822855753797805354139741959957951983943146108552762756444475545250343766798220348240377590112854890482375744876016191773471853704014735936608436210153669829454288199838827646402742554134017280213707222338496271289894681312606239512924842845268366950"
    )
    result = _run(
        "-e", "17,65537", "-n", n, "--decrypt", ct, "--attack", "same_n_huge_e"
    )
    assert result.returncode == 0


def test_nsif():
    n = "1078615880917389544637583114473414840170786187365383943640580486946396054833005778796250863934445216126720683279228360145952738612886499734957084583836860500440925043100784911137186209476676352971557693774728859797725277166790113706541220865545309534507638851540886910549436636443182335048699197515327493691587"
    result = _run("-n", n, "--attack", "nsif", "-e", "69212")
    assert result.returncode == 0


def test_recover_pq_from_ned():
    n = "89934323724424476294622381914221598261172812339375937399819972835334987445410253468222803336854810492858522510908818094465016971590866316799035894022707639444280657007098400914330738658538222266810030027839572053039403693393753168793586929250804215645550571352191199523184200836146013025928003383641371070393"
    d = "19962381665611835400733506106568527547878006333840452894627174646926439452040571847997880893864945423800493262831539082048043118936361632520188216585262183981035631032111326630882344091716101231068324973284629229989266282536689424414069614476142574917412326437716108488193134735278253062332252976826038348973"
    result = _run("--private", "-n", n, "-e", "65537", "-d", d)
    assert result.returncode == 0
