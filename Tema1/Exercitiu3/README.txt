In acest exercitiu am folosit 3 moduri de a cripta un plaintext: ECB, CBC si *CTR.

*CTR nu a fost predat, dar acesta seamana mult cu OFB, care transforma un block cipher intr-un stream cipher.
Acesta genereaza urmatorul block stream pe baza criptarii succesive a unui "counter". Counterul poate fi orice
functie care produce o secventa care garantat nu se va repeta(foarte mult timp).

Modul CTR a fost folosit la cheia K3, cea denumita drept provKey in nodurile A si B si de catre KM. Aceasta este cheia
pe care o detin nodurile la inceput si care va fi folosita in decriptarea cheilor primite de la KM.

Fiecare cheie si iv este creata random la fiecare executie a programului. Pentru cheie sunt generati 256 de bytes
random, iar pentru iv sunt generati 16 bytes random cu ajutorul functiei generateRandomBytes(n - numar intreg).

KM detine inca doua chei, in modul ECB si CBC. In functie de modul comunicat de catre nodul A la B si de catre nodul
A la KM, vom folosi unul din cele doua moduri mai sus.

Pasul 1: Programul incepe prin a desemna doua noduri, A si B. Acestor doua noduri le va fi atribuita cheia K3. Astfel,
se va simula comportamentul din viata reala.

Pasul 2: Nodul A va seta modul de operare dorit apoi va trimite un mesaj catre nodul B si catre KM. In functie de
modul de operare, KM va crea o cheie(ECB sau CBC) si o va cripta folosind K3*, cea care se afla si la A si B. Cheia
criptata este apoi trimisa de catre KM la nodurile A si B.

*de aici incolo vom face referire la K3 ca fiind cheia pe care o detin dinainte A, B si KM

Pasul 3:  Nodurile A si B vor decripta cheia primita de la KM folosind K3. B va trimite un mesaj catre A in care se
specifica faptul ca nodurile sunt gata de o comunicare securizata.

Pasul 4: Nodul A va trimite un mesaj catre B folosind cheia decriptata cu ajutorul cheii K3. Daca in ambele parti
cheia trimisa de catre KM a fost decriptata cu succes, atunci nodul B va putea decripta si citi mesajul trimis de A
fara nicio problema, ceea ce se si poate observa in cod.

Verificarea finala se face comparand textul din fisierul message.txt cu mesajul afisat in consola de catre nodul A.

Fisierele "*.h" se afla in folderul include
Fisierele "*.cpp" se afla in folderul src
Fisierul "*.txt" se afla in folderul text