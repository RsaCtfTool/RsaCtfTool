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
import Math.ContinuedFraction.Simple
import Control.Monad
import Data.List.GroupBy
import qualified Data.List as A
import Numeric.Statistics.Median
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


-- N bits mapping checking with ECM just products of two primers

nsf_find nbits range to = take to $ filter (\(v,c)-> length c==2) (map (\x-> (x,P.factorise x)) (nsf_map (nbits) range 0))

-- N bits mappingi without perfect squares or prime numers really slow checking primes, delete for faster mapping, pending chage to a fast comprobation 

nsf_map_nsq s x r =  filter (\(d)-> snd (integerSquareRootRem d) /= 0 ) (nsf_map s x r) 

ex = 1826379812379156297616109238798712634987623891298419

-- CHECK PERIOD LENGTH FOR N Using RSA
tryperiod n period = (powMod (powMod (2) ex n) (modular_inverse ex period) n) - (2) 

tryperiod2 n period m = (powMod (powMod (m) ex n) (modular_inverse ex period) n) - (m)
-- GET DIVISORS WITH ECM METHOD
divs n = read $ concat (tail (splitOn " " (show (divisors n))))::[Integer]

-- GET SUM OF FACTORS WITH ECM

sum_factors n = n + 1 - (totient n) 


-- DECIMAL EXPANSION, THE PERIOD



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
	| s > 133300= (0,0,0) 
	| t == 0 = out
	| otherwise = field_crack2 n (s+1) m
	where
	t = tryperiod2 n ((n)-s) m
	ns = n -s
	out = (n, s,ns)

field_crack n s
	| s > 100000= (0,0,0) 
	| t == 0 = out
	| otherwise = field_crack n (s+1)
	where
	s2 = (s*s)
	car = (div (n^2-s2) 2)
	t = tryperiod n car
	out = (n, s, car)


rep n x =
  if n == 1
    then [x]
    else x : rep (n-1) x

factof n =concat $  (map (\x-> rep ((read (show (snd x)))::Integer) (read ((splitOn " " ( show (fst x))) !! 1)::Integer)) (P.factorise n))

factdev n = out
	where
	(a,c,v)= field_crack n 0
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




main = do  
    args <- getArgs                  -- IO [String]
    progName <- getProgName          -- IO String
    print args
    let n = args !! 0
    let st = args !! 1
    let e = args !! 2
    let m = args !! 3

    let (publickey,field,devcarmichael) = field_crack (read n::Integer) (read st::Integer)
    putStrLn "Public Key" 
    
    print $ "N :"++(show publickey)

    print $ "E :"++(show ex)

    print $ "Testing message : "++m

    putStrLn "Field"

    print field

    putStrLn $ "Derivate Carmichael of N"

    print devcarmichael
    
    putStrLn $ "Derivate Private Key of N"

    print $ modular_inverse ex devcarmichael

    putStrLn $ "Original Private Key"

    print $ ""

    putStrLn $ "Factors"

    print $ "Q :"

    print $ "P :"
 
    putStrLn $ "Period , decimal expansion length"

    print $ " "
    --putStrLn "Carmichael of N Factors"

    --print $ factof devcarmichael
    
    putStrLn $ "Prime grimoire spells  v0.0.2"

