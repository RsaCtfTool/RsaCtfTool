ghc nsif.hs -o nsif
gcc -O3 -static nsif.c -lgmp -o nsifc
strip nsif
strip nsifc

