{-# LANGUAGE FlexibleContexts #-}

--Nos Santos Izquierdo Field , PRIME GRIMOIRE SPELLS v0.0.0.2
-- Authors
--  Enrique Santos
--  Vicent Nos

module Main where

import System.Environment
import System.Exit
import Distribution.Simple
import Data.List.Ordered
import Data.List.Split 
import Graphics.EasyPlot
import System.Console.CmdArgs
import System.Random
import System.Entropy
--import Math.ContinuedFraction.Simple
import Control.Monad
import Data.List.GroupBy
import qualified Data.List as A
--import Numeric.Statistics.Median
import Data.Numbers.Primes
import Control.Concurrent
import qualified Data.ByteString.Char8 as C
import qualified Data.List.Split as S2
import Math.NumberTheory.ArithmeticFunctions
import qualified Math.NumberTheory.Primes as P
import Math.NumberTheory.Powers.Modular
import Math.NumberTheory.Primes.Counting
import Codec.Crypto.RSA.Pure
import Data.Bits
import qualified Math.NumberTheory.Primes.Testing as MB
import qualified Data.Map as L
import Math.NumberTheory.Powers.Squares


-- COMPUTE CARMICHAEL DERIVATION
-- requiere n as a first .

nsf n s = (n^(2) - 1) -s


-- EXTRACT PRIVATE KEY WITH EXPONEN ANT N IN NSS NUMBERS 

nss_privatekey e n s= modular_inverse e (nsf n s)

-- EXTRACT FACTORS in NSF numbers

nsif_factorise_ecm n = (sg2-qrest, sg2+qrest) 
	where
	sigma = (n+1)-(totient n)
	sg2 = div sigma 2   
	qrest = integerSquareRoot ((sg2^2)-n)



nsif_factors n = take 1 $ filter (\(x,c)-> c*x==n && c>0 && c/=1 && c/=n ) $  map ( \x-> nsif_factorise n (n- (mod n x))) (nub $ sort (factdev n))


nsif_factors2 n = take 1 $ filter (\(x,c)-> c*x==n && c>0 && c/=1 && c/=n ) $  map ( \x-> nsif_factorise n (n- (mod n x))) (nub $ sort (factdev2 n 2))


nsif_dec_expansion n m= take 1 $ filter (\(x)-> powMod 10 x n==1 ) $ (nub $ sort (factdev n))++(nub $ sort $ (factdev2 n m))



nsif_factorise n t 
	| sg3 < 1 = (0,0)
	| otherwise = (sg2-qrest, sg2+qrest)
	where
	sigma = ((n+1))-(t)
	sg2 = div sigma 2   
	sg3 = sg2^2-n
	qrest = integerSquareRoot sg3

div_until_factor n t
	| t < 2 = (0,0)
	| gcdp /=1 && gcdp /= n = (gcd n p,gcd n q) 
	| otherwise = div_until_factor n (div t 2)
	where
	(p,q) = nsif_factorise n t
	gcdp = gcd n p


	


combinationsOf :: Int -> [a] -> [[a]]
combinationsOf 1 as        = map pure as
combinationsOf k as@(x:xs) = run (l-1) (k-1) as $ combinationsOf (k-1) xs
                             where
                             l = length as

                             run :: Int -> Int -> [a] -> [[a]] -> [[a]]
                             run n k ys cs | n == k    = map (ys ++) cs
                                           | otherwise = map (q:) cs ++ run (n-1) k qs (drop dc cs)
                                           where
                                           (q:qs) = take (n-k+1) ys
                                           dc     = product [(n-k+1)..(n-1)] `div` product [1..(k-1)]


-- MAP NSF PRODUCT OF PRIMES

-- N bits mapping

nsf_map s x r= map fst (filter (\(x,c)-> c==0) $ map (\x-> (x,tryperiod x (nsf x r))) ([2^s..2^s+x]))



nsf_map2 m s x r= map fst (filter (\(x,c)-> c==0) $ map (\x-> (x,tryperiod x (nsf x r))) ([m^s..m^s+x]))




-- N bits mapping checking with ECM just products of two primers

nsf_find nbits range to = take to $ filter (\(v,c)-> length c==2) (map (\x-> (x,P.factorise x)) (nsf_map (nbits) range 0))

-- N bits mappingi without perfect squares or prime numers really slow checking primes, delete for faster mapping, pending chage to a fast comprobation 

nsf_map_nsq m s x r =  filter (\(d)-> snd (integerSquareRootRem d) /= 0 ) (nsf_map2 m s x r) 

ex = 1826379812379156297616109238798712634987623891298419

-- CHECK PERIOD LENGTH FOR N Using RSA
tryperiod n period = (powMod (powMod (2) ex n) (modular_inverse ex period) n) - (2) 

tryperiod2 n period m = (powMod (powMod (m) ex n) (modular_inverse ex period) n) - (m)
-- GET DIVISORS WITH ECM METHOD
divs n = read $ concat (tail (splitOn " " (show (divisors n))))::[Integer]

-- GET SUM OF FACTORS WITH ECM

sum_factors n = n + 1 - (totient n) 


-- DECIMAL EXPANSION, THE PERIOD



ncrack n
	| p == 0 && p2 /= 0 = (n, ((prim n)^2 - (prim n))^2, p )
	| p2 == 0 && p /= 0 = (n, ((primb n)^2 - (primb n))^2, p2 )
	| otherwise = (n, (primb n)^2 - (primb n)-1, p )
	where

	pa =prim n

	pb = primb n 

	difp = ((prim n) - n )

	p = tryperiod2 (pa^2) (((pa)^2 - difp^2)^2 )  (2) 
	p2 = tryperiod2 (pb^2) (((pb)^2 - difp^2)^2) (2) 


--
--
-- Efficient way to calculate decimal expansion in semiprime numbers

-- With P Q
tpq p q = out
	where
	tp = div_until_mod_1 (p-1) (p-1)
	tq = div_until_mod_1 (q-1) (q-1)
	out = (lcm tp tq)


-- With N and ECM 
tn n = tp
	where
	c = carmichael n
	tp = div_until_mod_1 (c) (c)
	

div_until_mod_1 p last
	| period == 1 = div_until_mod_1 dp dp 
	| mp /= 0 = last
	| otherwise = last
	where
	(dp,mp) = divMod (p) 2
	period = powMod 10 dp (p+1)

pr = map (primes !!) [1..1000]

prs = nub $ sort ( concat (map (\x-> map (\y -> x*y) pr) pr ) )

field_crack2 n s m
	-- | mod n 3 == 0 = (0,0)
	-- | mod n 2 == 0 = (0,0)
	| s-isq > 11112= (0,0,0) 
	| ns /= 0 && t == 0 && s/=n = out
	| otherwise = field_crack2 n (s+1) (m)
	where
	s2 = s^2
	isq = (integerSquareRoot n)*2 
	t = tryperiod2 n (((prim n)^2)-((prim n)+s)) (m)
	check = powMod 2 ((prim n)^2-((prim n)+s)) n
	ns = (n^2) -s
	out = (n,s,ns)

field_crack n s m
	| s > 100000= (0,0,0) 
	| t == 0 = out
	| otherwise = field_crack n (s+1) m
	where
	s2 = (s*s)
	car = (div (n-s2) 2)
	t = tryperiod2 n car m
	out = (n, s, car)


findexp n t
	| m /= 0 = t
	| pw /= 1 && pw2 == 1 = t
	| pw == 1 && pw2 == 1 && m == 0 = findexp n (div t 2)
	| pw /= 1 && pw2 /= 1 = 0
	| otherwise = findexp n t 
	where
	(dt,m) = divMod t 2
	pw = powMod 10 (div t 2) n
	pw2 = powMod 10 t n 


prim n = read ((splitOn " " $ show (P.nextPrime n)) !! 1)::Integer

primb n = read ((splitOn " " $ show (P.precPrime n)) !! 1)::Integer

nsifc n base tries = (div n out, out)
	where
	primesc = nub $ sort $ map prim [1..n]	
	out = head $ filter (\x-> x/=1 && x/=2) $ map (\x-> gcd (n) (tryperiod2 ((n)) ((n)^2-x^2) x)) $ [2^base..2^base+tries]


sp s l = nub $ sort $  concat $ map (\x-> map (\y-> x*y) (map (\e-> prim (e*2) ) [(s)..(s)+l]) ) (map (\t-> prim (t*3)) [0,(s)..(s)+l])


ncr n f
	| f > 10 = (n,0,0,0)
	| tr3 == 1 && tr6 == 1= (n,car2,f,1)
	| tr4 == 1 = (n,car3,f,2)
	| tr5 == 1 = (n,car4,f,3)

	| tr7 == 1 && tr72 == 1 = (n,car5,f,4)
	| tr8 == 1 && tr82 == 1 = (n,car6,f,5)
	| tr9 == 1 && tr92 == 1 = (n,car7,f,6)

	| tr /= 1 || tr2 /= 1 = ncr n (((f+1)))
	| tr == 1 && tr2 == 1= (n,car,f,7)
	| otherwise = ncr n (f+1)
	where
	car = (n*(f))^2-(n*f)-(n*f+2)-1
	car2 = (n*(3^f))^2-(n*(3^f))-(n*(3^f)+2)-1
	car3 = (n*(4^f))^2-(n*(4^f))-(n*(4^f)+2)-1
	car4 = (n*(6^f))^2-(n*(6^f))-(n*(6^f)+2)-1
	car5 = (n*(5^f))^2-(n*(5^f))-(n*(5^f)+2)-1
	car6 = (n*(7^f))^2-(n*(7^f))-(n*(7^f)+2)-1
	car7 = (n*(8^f))^2-(n*(8^f))-(n*(8^f)+2)-1

	tr = powMod 10 car n
	tr2 = powMod 2 car n
	tr3 = powMod 10 car2 n
	tr6 = powMod 2 car2 n
	tr4 = powMod 10 car3 n
	tr5 = powMod 10 car4 n
	tr7 = powMod 10 car5 n
	tr8 = powMod 10 car6 n
	tr9 = powMod 10 car7 n

	tr52 = powMod 2 car4 n
	tr72 = powMod 2 car5 n
	tr82 = powMod 2 car6 n
	tr92 = powMod 2 car7 n




ncrk n 
	-- | tr3 == 1 = (n,tr3,car2,2)
	| tr2 == 1 = (n,tr2,car,1)
	| tr4 == 1 = (n,tr4,car3,3)
	| tr5 == 1 = (n,tr5,car4,4)
	| tr6 == 1 = (n,tr6,car5,5)
	| otherwise = (n,0,0,0)
	where
	m = n+2
	car = n^2-n-m-1
	-- car2 = (n*3)^2-n*3-(n*3+2)-1
	car3 = (n*9)^2-n*9-(n*9+2)-1
	car4 = (n*27)^2-n*27-(n*27+2)-1
	car5 = (n*81)^2-n*81-(n*81+2)-1
	tr = tryperiod2 (n*m) (car) (m)
	tr2 = powMod 10 (car) (n)	
	-- tr3 = powMod 10 (car2) (n)
	tr4 = powMod 10 (car3) (n)
	tr5 = powMod 10 (car4) (n)
	tr6 = powMod 10 (car5) (n)

cubecrack n = head $ filter (\x-> x/=1 && x/=n) $ map (\x-> gcd (n) (x^3-1)) [0,3..n+1000000000]

nos_sieve n s = take 6 $ filter (\(w,r)-> snd (w) == 1 ) $ map (\x-> (integerSquareRootRem ((n+x)),x)) $ concat $ map (\z->[z-1,z+1]) [s,s+6..s*5]


rsapoisoning n n2 
	| n-n2 > 125 = [0,0,0]
	| waveA /=1 = rsapoisoning n (n2-1)
	| otherwise = [n,devc]
	where
	--waveA = take 1 $ filter (\(a,d,v)-> v==0) $ map (\x-> ( n , x , tryperiod2 n (n^(x*10)-1) 2) ) $ tail $ [1..100] 
	devc = n2^2+n2
	waveA = powMod 10 devc n
--	waveB = powMod 10 (n2^2+n2) n
	


primetosquare n limit =	filter (\(d,r)-> snd  d== 1) $ map (\x-> ((integerSquareRootRem (n+x)),x) ) $ map (\x-> prim x) [1..(limit)]


{-
primetosquare :: Integer -> [Integer]
primetosquare n = candidates i i2
   where
   i = integerSquareRoot (n + 1)
   i2 = i^2
   candidates i i2
      -- | i > limit    = []
      | isPrime x    = x : candidates o o2
      | otherwise    = candidates o o2
      where 
      o2 = i2 + i + o   -- o2 = (i + 1)^2 = i^2 + i + (i + 1)
      o = i + 1
      x = o2 - n + 1  -- (n - 1 + x) must be a perfect square 
-}

{-
rsapoison n 
	| ln == 0 = (0,0,0)
	| otherwise = crk
	where
	ln = length $ head $ primetosquare n 10000000
	((prsqrt,r),f) = head $ primetosquare n 10000000
	crk = field_crack2 (n*f) 0 (n)

carnos n pr s 
	| s >= lpr = (0,0,0)
	| v == 0 = carnos n pr (s+1)
	| res2 /= 1 = carnos n pr (s+1)
	| res2 == 1 = (n,v,pro)
	| otherwise = carnos n pr (s+1) 
	where
	(r,f,v) = field_crack2 (n*pro) 0 (pro)
	lpr = length pr
	pro = pr !! s
	res2 = powMod 10 v n 

-}
rep n x =
  if n == 1
    then [x]
    else x : rep (n-1) x

factof n =concat $  (map (\x-> rep ((read (show (snd x)))::Integer) (read ((splitOn " " ( show (fst x))) !! 1)::Integer)) (P.factorise n))

factdev n = out
	where
	(a,c,v)= field_crack n 0 2
	e = factof v	
	out =nub $ sort $  map product $ tail $ A.subsequences e
	--out = e


factdev2 n m= out
	where
	(a,c,v)= field_crack2 n 0 m
	e = factof v	
	--out =nub $ sort $  map product $ tail $ A.subsequences e
	out = nub $ sort $ map (\x-> x*4) e 
	--out = e



cypher m n = powMod m ex n



nsif_decrypt m n s = out
	where
	s2 = (s*s)
	dev = div (n^2-s2) 2
	dcr = powMod m (modular_inverse ex dev) n
	out = (dcr,dev)

	



loadkeys = do 
	-- a file with pubkeys in integer format separated by lines
	a<-readFile "testkeys.txt"
	let c=S2.splitOn "\n" a
	let ns=map (\x->read x::Integer) (filter (/="") c)
	return $ ns


-- Decimal expansion in a traditional slow way
period n = (length (takeWhile (/=1) $ map (\x -> powMod 10 x n ) ( tail [0,1..n])) ) +1

-- All who decodes msg integer input
-- in diferent kind of field

alldecnss n = filter (\(c)-> tryperiod n (n^2) == 0 || tryperiod n (n^2 - c-1)==0 || tryperiod n (n^2 + c-1) == 0 ) $ (tail [0,3..n])


alldec2 n = take 1000 $ filter (\(z,y) -> y == 0 ) (map (\x-> (x , tryperiod n ((x^2) - (x*6))) ) (reverse [1..n]))


alldec n = filter (\(z,y) -> y == 0) (map (\x->(x,tryperiod n x)) [1..n])

{--
rsapoison n prim
	| fc == (0,0,0) = repoison n pri b
	| fc /= (0,0,0) = fc
	where
	lo = logBase 2 n
	pri = genprimes 3 lo
	newn = (product (pri))*n
	fc = field_crack newn 0 $ product pri 


genprimes n b = [a1,a2,a3] 
	where
	a1 = (splitOn " " $ show (P.nextPrime (rnd (2^b) (2^b+20000) ) )) !! 1
	a2 = (splitOn " " $ show (P.nextPrime (rnd (2^b) (2^b+20000) ) )) !! 1
	a3 = (splitOn " " $ show (P.nextPrime (rnd (2^b) (2^b+20000) ) )) !! 1
 --}

main = do  
    args <- getArgs                  -- IO [String]
    progName <- getProgName          -- IO String
    print args
    let n = args !! 0
    let st = args !! 1
    let e = args !! 2
    let m = args !! 3

    let (publickey,factors) = nsifc (read n::Integer) (read st::Integer) (read m::Integer)
    putStrLn "Public Key" 
    
    print $ "N :"++(show publickey)

    putStrLn $ "Factors"

    print $ factors
 

    print $ " "
    
    putStrLn $ "Prime grimoire spells  v0.1"

