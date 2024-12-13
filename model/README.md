# Modelovanje pretnji nad Apache Hadoop sistemom

Tema modale pretnji jeste Apache Hadoop sistema.

Na dijagramu tokova podataka, slika 1, predstavljena je osnovna postavka Apache Hadoop sistem. Prikazane su ključne komponente na najvišem nivou apstrakcije prilikom modelovanja.

![Apstraktni dijagram](./Apstraktni_dijagram.png)

_Slika 1. Dijagram tokova podataka na najvišem nivou apstrakcije._

## Dijagrami tokova podataka

![Dekomponovan dijagram](./Kompletan_dijagram.png)

_Slika 2. Dijagram tokova podataka dekomponovan na višem nivou detaljnosti._

**Napomena:** S obzirom da se resurs R1 propagira kroz čitav sistem, nije predstavljen na dijagramu kako ga ne bi opteretio.

Potrebno je pojasniti svaki element dijagrama i predstavljenog modela ponaosob. **_Clients_** predstavljaju eksterni entitet i to bi bili korisnici ili aplikacije koje mogu komunicirati pomoću Hadoop CLI-a, WebHDFS-a i slično. Neophodno je obaviti adekvatno autentifikaciju i autorizaciju svakog korisnika, to se postiže zahvaljujući eksternom entitetu **_Kerberos_**. Ukoliko bi klijenti na primer uputili zahtev za upis podataka, tada bi se kontaktirao **_HDFS_**. Konkretnije, procesni čvor **_NameNode_** enkapsulira sve zadatke i operacije koje se izvršavaju zarad obavljanja operacije čitanja podataka. **_NameNode_** u svakom trenutku zna gde se koji blokovi podataka nalaze na osnovu skladišta podataka _**Metadata files**_. Time mu je omogućeno da adekvatno odgovori na postavljeni zahtev korisnika kroz dobavljanje podataka od odgovarajućih _**DataNode-ova**_. Sami _**DataNode-ovi**_ sem skladištenja blokova podataka u datotekama, skladište i logove kao i konfiguracione fajlove, što je na dijagramu specificirano kao skladišta _**Files, logs i config file**s_. Kada se šalje zahtev za obradom **_MapReduce_** zadataka situacija je nešto drugačija. Tada je u proces uključen **_YARN_** koji fundamentalno predstavlja _**Resource Manager**_. Sam **_YARN_** ima svoje skladište podataka koje je privremenog karaktera, ali je izuzetno važno jer se u njemu beleže sve neophodne informacije za **_MapReduce_** zadatke koji su u toku ili bi trebalo uskoro da počnu. 

## Resursi i pretnje visokog nivoa

Na slici 3 je predstavljen dijagram toka podataka Apache Hadoop sistema dekomponovan na višem nivou detaljnosti sa prikazanim kritičnim resursima. U tabeli ispod slike su navedeni svi kritični resursi.  

![Dekomponovan dijagram](./Dijagram_sa_resursima.png)

_Slika 3. Dijagram tokova podataka sa prikazom resursa._

| ID | Kritični resursi |
| -- | ------ |
| R1 | Tokeni (TGT, delegacioni, block access, job tokeni i slični) |
| R2 | Konfiguracioni fajlovi |
| R3 | Blokovi podataka (*) |
| R4 | Poslovi i zadaci |
| R5 | Alocirani računarski resursi: RAM, CPU i stalna memorija (*) |
| R6 | Rezultati |
| R7 | Informacije o kontejnerima |
| R8 | Logovi i informacije o sistemu |

_Tebela 1. Dijagram tokova podataka sa prikazom resursa._

\* U zavisnosti od procesnog čvora mogu predstavljati i metapodatke, ne i same podatke.

U nastavku je analiziran svaki kritični resurs kroz prizmu mogućih napada bezbednosono svojstvo resursa koje napad narušava. 

| IDR | Kritični resursi | IDP | Pretnje | Tip
| -- | ------ | ----- | --- | --- | 
| R1 | Tokeni (TGT, delegacioni, block access, job tokeni i slični) | P11 | Krađa tokena ili zloupotreba tokena | S, E, I 
|  |  | P12|  SQL injekcija kroz nevalidiran HTTP zahtev | S, T, R, I, D, E 
|  |  | P13|  Komandne injekcije zahvaljujući ranjivom parsiranju komandi (ranjiv CLI) | S, T, R, I, D, E 
|  |  | P14|  Neadekvatne autorizacije | S, T, I
|  |  | P15|  Napad velikim broj zahteva kako bi se izvršilo zagušenje API servisa | D
| R2 | Konfiguracioni fajlovi | P21 | Manipulacija konfiguracionim fajlovima može promeniti stanje sistema radi uvođenja ranjivosti | T, I, D
|  |  | P22|  Narušavanje poverljivosti konfiguracionih fajlova | I
| R3 | Blokovi podataka (*) | P31 | Napadač želi da na maliciozni način upravlja podacima (čita, briše, upisuje) čime potencijalno narušava integritet, poverljivost i dostupnost. | D, T, I
| | | P32 | Slanje prevelikog broja zahteva radi postizanja nedostupnosti sistema. | D
| R4 | Poslovi i zadaci |P41| Slanje prevelikog broja poslova kako bi se izvršilo opterećenje *ApplicationManager* komponente.  | T, D 
| | | P42 | Podmetanje malicioznih poslova kako bi se ostvarile štetne operacije. | T, D, I, E
| R5 | Alocirani računarski resursi: RAM, CPU i stalna memorija (*) | P51 | Podmetanje malicioznog posla koji alocira velike količine računarskih resursa.  | D, T
| R6 | Rezultati | P61 | Promena međurezultata kako bi se uticalo na tačnost konačnih rezultata | T, E, I
| R7 | Informacije o kontejnerima | P71| Lažiranje informacija o resursima kontejnera zarad ostvarivanja više resursa | T, D
| | | P72 | Podmetanje malicioznih kontejnera | S, T, D
| | | P73 | Preopterećenje ili rušenje kontejnera | D
| | | P74 | Zloupotreba kontejnera radi postizanja većih privilegija | E
| R8 | Logovi i informacije o sistemu | P81 | Lažiranje logova u cilju sabotaže sistema | T, I, R, S

_Tebela 2. Prikaz potencijalnih napada na resurse._

## Literatura
           
1. Terminologija korišćena u ovom dokumentu je definisana na sledećem [linku](https://github.com/Luburic/zoss-model-pretnji/blob/main/modeli/terminologija.md).
                
                    
