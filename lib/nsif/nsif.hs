{-# LANGUAGE FlexibleContexts #-}

--Nos Santos Izquierdo Field , PRIME GRIMOIRE SPELLS v0.0.0.2
-- Authors
--  Enrique Santos
--  Vicent Nos

module Main where

import System.Environment
import System.Exit
import System.Console.CmdArgs

import Data.List.Ordered
import Data.List.Split 
import Data.List (subsequences)

import Data.Numbers.Primes
import qualified Math.NumberTheory.Primes as P
import Math.NumberTheory.ArithmeticFunctions
import Math.NumberTheory.Powers.Modular
import Math.NumberTheory.Powers.Squares
import Codec.Crypto.RSA.Pure


-- COMPUTE CARMICHAEL DERIVATION
-- requiere n as a first .

nsf n s = (n^2 - 1) - s


-- EXTRACT PRIVATE KEY WITH EXPONEN ANT N IN NSS NUMBERS 

nss_privatekey e n s = modular_inverse e (nsf n s)

-- EXTRACT FACTORS in NSF numbers


nsif_factors n = take 1 . filter ( \(x,c) -> c*x == n && c > 1 && c /= n ) 
   . map ( \x -> nsif_factorise n (n - mod n x) ) $ factdev n


nsif_factors2 n = take 1 $ filter ( \(x,c) -> c*x == n && c > 1 && c /= n ) 
   . map ( \x -> nsif_factorise n (n - mod n x) ) $ factdev2 n 2


nsif_dec_expansion n m = take 1 . filter ( \x -> powMod 10 x n == 1 ) 
   . nub . sort $ factdev n ++ factdev2 n m



nsif_factorise_ecm n = nsif_factorise n (totient n)
-- nsif_factorise_ecm n = (sg2 - qrest, sg2 + qrest) 
   -- where
   -- sigma = (n + 1) - (totient n)
   -- sg2 = div sigma 2   
   -- sg3 = sg2^2 - n
   -- qrest = integerSquareRoot sg3


nsif_factorise n t 
   | sg3 <= 0  = (0,0)
   | otherwise = (sg2 - qrest, sg2 + qrest)
   where
   sigma = (n + 1) - t  -- if n=p*q, and t=totient(n), then, sigma = p + q
   sg2 = div sigma 2 
   sg3 = sg2^2 - n
   qrest = integerSquareRoot sg3

div_until_factor n t
   | t <= 1 = (0,0)
   | gcdp /= 1 && gcdp /= n = (gcdp, gcd n q) 
   | otherwise = div_until_factor n (div t 2)
   where
   (p,q) = nsif_factorise n t
   gcdp = gcd n p


combinationsOf :: Int -> [a] -> [[a]]
combinationsOf 1 as        = map pure as
combinationsOf k as@(x:xs) = run l k1 as $ combinationsOf k1 xs
   where
   l  = length as - 1
   k1 = k - 1

   run :: Int -> Int -> [a] -> [[a]] -> [[a]]
   run n k ys cs 
      | n == k    = map (ys ++) cs
      | otherwise = map (q :) cs ++ run (n - 1) k qs (drop dc cs)
      where
      (q:qs) = take (n - k1) ys
      dc     = product [n - k1 .. n - 1] `div` product [1 .. k1]


-- MAP NSF PRODUCT OF PRIMES

-- N bits mapping

-- nsf_map s x r     = filter (\x -> tryperiod x (nsf x r)) [2^s .. 2^s + x]
nsf_map = nsf_map2 2

nsf_map2 m s x r  = filter (\x -> tryperiod x (nsf x r)) [m^s .. m^s + x]


-- N bits mapping checking with ECM just products of two primers

nsf_find nbits range to = take to 
   . filter (\(_, c) -> length c == 2) 
   . map (\x -> (x, P.factorise x)) 
   $ nsf_map nbits range 0

-- N bits mappingi without perfect squares or prime numers really slow checking primes, delete for faster mapping, pending chage to a fast comprobation 

nsf_map_nsq m s x r =  filter (\d -> snd (integerSquareRootRem d) /= 0) $ nsf_map2 m s x r

-- GET DIVISORS WITH ECM METHOD
divs n = read $ concat (tail (splitOn " " (show (divisors n))))::[Integer]

-- GET SUM OF FACTORS WITH ECM

sum_factors n = n + 1 - totient n


-- DECIMAL EXPANSION, THE PERIOD



-- Efficient way to calculate decimal expansion in semiprime numbers

-- With P Q
tpq p q = out
   where
   tp = div_until_mod_1 (p-1) (p-1)
   tq = div_until_mod_1 (q-1) (q-1)
   out = lcm tp tq


-- With N and ECM 
tn n = tp
   where
   c = carmichael n
   tp = div_until_mod_1 c c
   

div_until_mod_1 p last
   | period /= 1  = last
   | otherwise    = div_until_mod_1 dp dp 
   where
   dp = div p 2
   period = powMod 10 dp (p + 1)

findexp n t
   | m /= 0 = t
   | pw /= 1 && pw2 == 1 = t
   | pw /= 1 && pw2 /= 1 = 0
   | pw == 1 && pw2 == 1 = findexp n dt
   | otherwise           = findexp n t 
   where
   (dt,m) = divMod t 2
   pw  = powMod 10 dt n
   pw2 = powMod 10 t n 



ex = 1826379812379156297616109238798712634987623891298419

-- CHECK PERIOD LENGTH FOR N Using RSA
tryperiod n period = tryperiod2 n period 2

-- | Cypher 'm' and tries to uncypher using 'period' as the privKey
tryperiod2 n period m = powMod c xe n == m
   where
   c  = powMod m ex n -- cypher m n
   xe = modular_inverse ex period
   

cypher m n = powMod m ex n


nsif_decrypt m n s = (dcr, dev)
   where
   dev = div (n^2 - s^2) 2
   dcr = powMod m (modular_inverse ex dev) n

   
field_crack2 n s m
   -- | mod n 3 == 0 = (0,0)
   -- | mod n 2 == 0 = (0,0)
   | s > 1313300  = (0,0,0) 
   | t && ns /= 0 = (n, s, ns)
   | otherwise    = field_crack2 n (s + 1) m
   where
   ns = n^2 - s
   t = tryperiod2 n ns m

field_crack n s m
   | s > 100000 = (0,0,0) 
   | t          = (n, s, car)
   | otherwise  = field_crack n (s + 1) m
   where
   car = div (n^2 - s^2) 2
   t = tryperiod2 n car m



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


rsapoison :: Integer -> (Integer, Integer, Integer)
rsapoison n = field_crack2 (n + f) 0 f
   where
   f = head $ primetosquare n



rsapoisoning n = [waveA, waveB]
   where
   sq = integerSquareRoot n
   waveA = field_crack2 ( (n + 1) + (sq + 1)^2 ) 0 sq
   waveB = field_crack2 ( (n - 1) - (sq - 1)^2 ) 0 sq
   -- a  = n + 2*sq + 2 + sq^2
      -- = (n + 2) + (sq + 2)*sq
      -- = (n + 1) + (sq + 1)^2
      
   -- b  = n + 2*sq - 2 - sq^2
      -- = (n - 2) - (sq - 2)*sq
      -- = (n - 1) - (sq - 1)^2


carnos n pr s 
   | s >= lpr  = (0,0,0)
   | res2 /= 1 = carnos n pr (s + 1)
   | v == 0    = carnos n pr (s + 1)
   | otherwise = (n,v,pro)
   where
   (r,f,v) = field_crack2 (n*pro) 0 pro
   lpr = length pr
   pro = pr !! s
   res2 = powMod 10 v n 


pr = map (primes !!) [1 .. 1000]

-- prs = nub . sort $ concatMap (\x-> map (\y -> x*y) pr) pr 
prs = sort $ [x*y | x <- pr, y <- pr, x <= y]

-- sp = nub . sort $ concatMap ( \x -> map (\y -> x*y) primeList ) primeList
sp = sort $ [x*y | x <- primeList, y <- primeList, x <= y]
   where
   primeList = map (primes !!) [2^17 .. 2^17 + 20]

-- rep 1 x = [x]
-- rep n x = x : rep (n - 1) x

factof n = concatMap (\x -> replicate ((read (show (snd x)))::Int) (read ((splitOn " " ( show (fst x))) !! 1)::Integer)) (P.factorise n)

factdev n = out
   where
   (a,c,v)= field_crack n 0 2
   e = factof v   
   out = nub . sort . map product . tail $ subsequences e
   --out = e


factdev2 n m = out
   where
   (a,c,v) = field_crack2 n 0 m
   e = factof v   
   --out = nub . sort . map product . tail $ subsequences e
   out = nub . sort $ map (* 4) e 
   --out = e



loadkeys = do 
   -- a file with pubkeys in integer format separated by lines
   a <- readFile "testkeys.txt"
   let c = splitOn "\n" a
   let ns = map (\x -> read x::Integer) (filter (/= "") c)
   return $ ns


-- Decimal expansion in a traditional slow way
period n = 1 + length (takeWhile (/= 1) $ map (\x -> powMod 10 x n ) [1 .. n])

-- All who decodes msg integer input
-- in diferent kind of field

alldecnss n = filter (\c -> tryperiod n (n^2) || tryperiod n (n^2 - c - 1) || tryperiod n (n^2 + c - 1) ) $ (tail [0,3 .. n])


alldec2 n = take 1000 . filter snd . map (\x-> (x , tryperiod n (x^2 - x*6)) ) $ reverse [1 .. n]


alldec n = filter snd (map (\x -> (x, tryperiod n x)) [1 .. n])

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
    let (n : st : e : m : _) = args
    -- let n = args !! 0
    -- let st = args !! 1
    -- let e = args !! 2
    -- let m = args !! 3

    let (publickey, field, devcarmichael) = field_crack (read n::Integer) (read st::Integer) (read m::Integer)
    
    putStrLn "Public Key" 
    
    print $ "N :" ++ show publickey

    print $ "E :" ++ show ex

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
