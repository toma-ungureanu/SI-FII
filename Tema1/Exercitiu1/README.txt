In acest exercitiu vom cripta un mesaj si, fara a detine cheia, ci doar IV, vom face brute force pana obtinem mesajul
initial.

Functia readFromFile are ca parametru un string ce reprezinta path-ul fisierului pe care vrem sa il citim si intoarce
un string reprezentand textul citit sau un string gol in caz de eroare

Functia getPossiblePasswords preia toate parolele de 15 caractere posibile din fisierul words.txt(cheia trebuie sa aiba
dimensiunea de 16 bytes, asa ca vom face un padding de un byte pana la 16)

Functia passwordGenerator alege o parola random din toate parolele posibile pe care le-am preluat mai sus

Functia encrypt foloseste standardul OpenSSL EVP API pentru a cripta un text, avand ca paramteri plain textul,
dimensiunea acestuia, IV, cheia de criptare, si metoda de criptare (ECB, CBC)
EVP_EncryptInit_ex initializeaza un context cu ajutorul cheii de criptare, IV si modului de criptare folosit
EVP_EncryptUpdate cripteaza bytes si ii atribuie parametrului de iesire
EVP_EncryptFinal (daca paddingul este activ, default in cazul nostru) cripteaza datele "finale", adica orice poate
ramane intr-un bloc partial, cu o dimensiune mai mica decat un bloc normal* si le atribuie parametrului de out

*Pentru a ajunge la dimensiunea unui bloc normal folosind datele care au ramas, vom folosi PKCS padding.
Aceasta adauga n bytes de padding de valoare n pentru ca lungimea totala a datelor criptate sa fie un multiplu de
dimensiunea blocurilor. Paddingul este intotdeauna adaugat, asadar daca datele sunt deja un multiplu de dimensiunea
blocurilor, n va fi egal cu dimensiunea blocurilor.
EX:
Daca dimensiunea blocului este 8 si 11 mai raman de criptat, 5 bytes de padding cu valoarea value 5 vor fi adaugati.

EVP_DecryptFinal va returna o eroare daca paddingul este activ si blocul final nu este format corect, ca mai sus.

Functia brute force incearca fiecare parola din fisierul word.txt. Daca parola nu este cea corecta, EVP_DecryptFinal va
intoarce o eroare, BAD_DECRYPT.

EX:
Daca dorim sa criptam 11 bytes, textul criptat final va avea 16 bytes. Avand paddingul activ, stim ca ultimii 5 bytes
ar trebui sa fie cu valoarea 5, daca vom folosi parola buna si acestia vor fi dati la o parte. Altfel, functia va
decripta primii 8 bytes, dar ultimii 8 ii va lua drept un singur bloc fara padding, iar paddingul nu va putea fi
observat. Astfel, vom avea 5 trailing bytes cu valoarea 5, ceea ce va insemna un cod de eroare pentru functia
EVP_DecryptFinal.

Fisierele "*.txt" pot fi gasite in folderul text
