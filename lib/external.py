TIMEOUT = 600
MSIEVE_BIN = os.environ.get("MSIEVE_BIN", "NONE") 
YAFU_BIN   = os.environ.get("YAFU_BIN",   "NONE")
CADO_BIN   = os.environ.get("CADO_BIN",   "NONE") 


def msieve_factor_driver(n):
  global MSIEVE_BIN
  print("[*] Factoring %d with msieve..." % n) 
  tmp = []
  proc = subprocess.Popen([MSIEVE_BIN,"-s","/tmp/%d.dat" % n,"-t","8","-v",str(n)],stdout=subprocess.PIPE)
  for line in proc.stdout:
    line = line.rstrip().decode("utf8")
    if re.search("factor: ",line):
      tmp += [int(line.split()[2])]
    if DEBUG:
      print(line)
  #os.system("rm /tmp/%d.dat" % n)
  ifferm("/tmp/%d.dat" % n)
  return tmp


def yafu_factor_driver(n):
  global YAFU_BIN, TIMEOUT
  print("[*] Factoring %d with yafu..." % n)
  tmp = []
  proc = subprocess.Popen(["timeout",str(TIMEOUT),YAFU_BIN,"factor(%s)" % str(n),"-session",str(n),"-qssave","/tmp/qs_%s.dat" % str(n)],stdout=subprocess.PIPE)
  for line in proc.stdout:
    line = line.rstrip().decode("utf8")
    if re.search("P\d+ = \d+",line):
      tmp += [int(line.split("=")[1])]
    if DEBUG:
      print(line)
  #  print("o",end="")
  #print("")
  #os.system("rm /tmp/qs_%d.dat" % n)
  ifferm("/tmp/qs_%d.dat" % n)
  return tmp


def yafu_factor_driver(n):
  return 


def external_factorization(n):
  factors = yafu_factor_driver(n)
  if len(factors) == 0:
    factors = msieve_factor_driver(n)
  return factors
