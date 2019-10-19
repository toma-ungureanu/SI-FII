In acest exercitiu vom calcula hash-urile a doua fisiere text care difera printr-un singur caracter.
Pentru aceasta am folosit functiile hash MD5 si SHA256

Pasul 1: Am citit din fisier cele doua texte apoi le-am criptat cu MD5, respectiv SHA256 folosind functia encrypt,
care foloseste functii din standardul OpenSSL EVP

Pasul 2: Am citit hash-urile celor doua texte si le-am comparat. Pentru un text de 172 de caractere, nici la MD5 si
nici la SHA256 nu avem coliziuni de bytes, dupa cum poate fi revazut in in rezultatul de pe consola.

Functia readFromFile are ca parametru un string ce reprezinta path-ul fisierului pe care vrem sa il citim si intoarce
un string reprezentand textul citit sau un string gol in caz de eroare

Functia writeToFile foloseste functii din standardul OpenSSL, si anume BIO_printf pentru a printa un sir de bytes
intr-un fisier dat ca parametru. Pentru aceasta vom folosi obiecte OpenSSL si anume BIO (Byte Input/Output)

Functia sameByteOccurence primeste ca parametru doua texte si verifica daca avem bytes care sunt identici in ambele
hash-uri, pe pozitii identice

Functia encrypt foloseste standardul OpenSSL, EVP API pentru a crea hash-ul unui text data ca parametru si functia
hash dorita.
EVP_DigestInit initializeaza un context care va primi datele create de functia hash impreuna cu textul
EVP_DigestUpdate foloseste functia hash primita si textul pentru a atribui bytes hash-uiti contextului
EVP_DigestFinal prea bytes din context si ii atribuie parametrului de iesire

Fisierele "*.txt" se gasesc in folderul text