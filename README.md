# Modelovanje pretnji nad _Apache Hadoop_ modulom

Kada je reč o velikim skupovima podataka upotreba ovog modula je nezaobilazna [[2]](#[2]). Njegova snaga leži u osobini distribuiranog skladištenja i obrade podataka. _Hadoop_ klasteri su po svojoj prirodi vrlo kompleksni, jer ih čine mnoštvo komponenti koje sinhrono funkcionišu kao jedna celina. Komponente vrlo često komuniciraju i razmenjuju podatke kako bi adekvatno odgovorile na zahteve korisnika. Pošto je reč o ovako složenom modulu, on je vrlo interesantan sa aspekta bezbednosti, kako od strane malicioznih korisnika, tako i od strane osoblja zaduženog za očuvanje njegove bezbednosti. 

Na dijagramu toka podataka, slika 1, predstavljena je osnovna postavka _Hadoop_ modula. Prikazane su ključne komponente na najvišem nivou apstrakcije prilikom modelovanja.

![Apstraktni dijagram](./Apstraktni_dijagram.svg)

_Slika 1: Dijagram toka podataka na najvišem nivou apstrakcije_

## Dekompozicija modula
U zavisnosti od postavke _Hadoop_ klastera moguće je uključivanje različitih komponenti. U zavisnosti od tipa komponente moguće je povećati površinu za napad, ali i adekvatnije upravljati bezbednošću. Na primer, uvođenjem _ZooKeeper_ ili _Kerberos_ komponente modul će povećati stepen bezbednosti. Uvođenjem komponente kao što je _Apache Hive_ se povećava površina za napad, jer se uvodi komponenta koja nije jezgro (engl. _core_) _Hadoop_ modula. Pitanjem bezbednosti klastera je moguće baviti se na sledeća tri načina:
1. Oslanjanjem na bezbednosne mehanizme operativnog sistema.  
2. Oslanjanjem na _Hadoop_ bezbednosne mehanizme.
3. Oslanjanjem na eksterne komponente koje postižu veći stepen bezbednosti.

Najrealnije sagledavanje nekog modula sa aspekta bezbednosti bi bilo kroz osnovne (podrazumevane) nivoe zaštite, što će se imati na umu tokom ovog istraživačkog rada. 

![Dekomponovan dijagram](./Kompletan_dijagram.svg)

_Slika 2: Dijagram toka podataka dekomponovan na višem nivou detaljnosti_

U nastavku će biti pojašnjeni elementi dijagrama analiziranog modula.

_Clients_ predstavljaju eksterni entitet i to bi bili korisnici ili aplikacije koje mogu komunicirati pomoću _Hadoop CLI-a, WebHDFS-a_, biblioteka programskih jezika i slično. Aplikacija u zavisnosti od konteksta može predstavljati korisnika ili biti sinonim za poslove. 

#### Hijerahija odnosa
Potrebno je objasniti hijerarhiju odnosa između čvorova. Uvode se pojmovi nadređeni (engl. _master_) i podređeni (engl. _slave_) čvor. 
Čvor može biti _Docker_ kontejner, virtuelna mašina ili server. Obratiti pažnju, procesni čvor nije uvek isto što i čvor, iako najčešće jeste.
- U okviru _YARN_ komponente, _ResourceManager_ je nadređeni čvor, pri čemu su _NodeManager-s_ podređeni čvorovi [[3]](#[3]).
- U okviru _HDFS_ komponente, _NameNode_ je nadređeni čvor, pri čemu su _DataNode-s_ podređeni čvorovi [[4]](#[4]).

![Master-slave hijerarhija](./Master_slave_hijerarhija.svg)

_Slika 3: Dijagram master-slave hijerarhije odnosa_

Procesni čvorovi _Scheduler_ i _ApplicationManager_, su posledično nadređeni procesnim čvorovima _ApplicationMaster_, _NodeManager_ i _Container_. Takođe, procesni čvor _NameNode_ je nadređen _DataNode_ procesnim čvorovima.

Sa aspekta bezbednosti bitno je razumeti ove odnose kako bi se adekvatno definisale granice poverenja.

#### Tipovi zahteva
Klijentski zahtevi se načelno dele na dva tipa:
1. Zahtevi za rad nad podacima — Ova vrsta zahteva odnosi se na čitanje, upis, brisanje ili izmenu podataka.
2. Zahtevi za pokretanje poslova — Ova grupa obuhvata zahteve za prosleđivanje poslova (engl. _job_ ili _application_), pri čemu je _MapReduce_ najčešći tip posla. 

###### Zahtev za čitanje podataka
Ukoliko bi klijent uputio zahtev za čitanje podataka, tada bi se kontaktirala _HDFS_ komponenta. Konkretnije govoreći, procesni čvor _NameNode_, koji enkapsulira sve zadatke i operacije koje se izvršavaju zarad obavljanja operacije čitanje podataka. _NameNode_ u svakom trenutku zna gde se koji blokovi podataka nalaze na osnovu skladišta podataka _Metadata_. Ovime je omogućeno da adekvatno odgovori na postavljeni zahtev korisnika kroz dobavljanje podataka od odgovarajućih _DataNode-ova_. Sami _DataNode-ovi_ skladište blokove podataka u specijalizovanom distribuiranom sistemu datoteka, što je na dijagramu specificirano kao skladište _Blocks_.
###### Zahtev za pokretanje posla
Kada se šalje zahtev za obradom _MapReduce_ posla situacija je nešto drugačija. Tada je u proces uključen čitav _Hadoop_ modul. _YARN_ komponenta poput _HDFS_ komponente prožima više elemenata. Ipak, fundamentalna komponenta predstavlja _ResourceManager_ koja se deli na _Scheduler_ i _ApplicationManager_ procesne čvorove. _Scheduler_ procesni čvor ima centralnu ulogu u _YARN_ komponenti.  Uloga _Scheduler_ procesnog čvora je nadgledanje resursa praktično svih procesnih čvorova i dodeljivanje resursa kako bi se realizovali poslovi. Procesni čvorovi u okviru _ResourceManager_ komponente  čuvaju u radnoj memoriji podatke o resursima (_Resources_) i poslovima (_Applications_) radi brzine pristupa. Takođe, oni te podatke povremeno čuvaju i u _Blocks_ skladištu podataka, kako bi lakše nastavili svoj posao u slučaju prekida posla ili manje opteretili sebe radi čitanja podataka o statusu aplikacija.  
_Applications_ skladište podataka je izuzetno važno jer se u njemu beleže sve neophodne informacije za _MapReduce_ poslove koji su u toku ili bi trebalo uskoro da počnu.  Svaki posao koji pristigne od klijenta se razbija na zadatke. Posao inicijalno biva prosleđen _ApplicationManager_ procesnom čvoru, koji zahteva resurse za pokretanje kontejnera u okviru kog se izvršava _ApplicationMaster_. Zatim _ApplicationMaster_ preuzima inicijativu i odgovornost, pa u dogovoru sa _Scheduler_ komponentom "ispregovara" resurse neophodne za _Map_ zadatke, a kasnije i za _Reduce_ zadatke. Osnovna uloga _ApplicationMaster_ procesnog čvora je planiranje i  upravljanje realizacijom zadataka, dok je sporedna uloga pregovaranje za dodatnim resursima sa _Scheduler_ komponentom. Svaki _Map_ kontejner će proizvesti međurezultate koji će se kasnije agregirati zahvaljujući _Reduce_ kontejnerima i upisati u _Blocks_.

_Config_ skladište predstavlja konfiguracione fajlove koji se definišu na nivou čvora. Na nivou čvora mogu biti definisane konfiguracije za više procesnih čvorova. Na nivou _Hadoop_ modula posvećena im je posebna pažnja. Ako bi se posmatrao neki čvor, on bi morao imati definisane konfiguracione fajlove:
- za sve procesne čvorove koje on sadrži,
- za sve procesne čvorove sa kojima se obavlja komunikaciju,
- za sve čvorove koji čine _Hadoop_ modul.

Dakle, praktično svaki čvor poseduje kopiju većine konfiguracionih fajlova. 

Slična je situacija sa _Log_ skladištem, s tim da su bezbednosna svojstva fajlova te vrste manje značajna. Ipak, ne treba ih zanemariti.

## Resursi i pretnje visokog nivoa

Na slici 4 je predstavljen dijagram toka podataka _Hadoop_ modula dekomponovan na višem nivou detaljnosti sa prikazanim kritičnim resursima. U tabeli ispod slike su navedeni svi kritični resursi.  

![Dekomponovan dijagram](./Kompletan_dijagram_sa_resursima.svg)

_Slika 4: Dijagram tokova podataka sa prikazom resursa_

| ID | Kritični resursi |
| -- | ------ |
| R1 | Konfiguracioni fajlovi |
| R2 | Blokovi podataka |
| R3 | Alocirani računarski resursi `*` |
| R4 | Poslovi i zadaci |
| R5 | Rezultati |
| R6 | Informacije o statusu |
| R7 | Logovi |
| R8 | Meta-podaci |

_Tebela 1: Dijagram tokova podataka sa prikazom kritičnih resursa_

**Napomene:** 
- U slučaju direktne veze procesnog čvora sa skladištem podrazumeva se upotreba podataka tog skladišta.
- `R*` govori da se svi kritični resursi mogu naći na procesnom čvoru klijentskog interfejsa.
- `*` u zavisnosti od procesnog čvora mogu predstavljati metapodatke.

U nastavku je analiziran svaki kritični resurs kroz prizmu mogućih pretnji, zatim su određena bezbednosna svojstva resursa, koje pretnje, ukoliko su realizovane, mogu narušiti. 

| IDR | Kritični resursi | IDP | Pretnje | STRIDE tip
| -- | ------ | ----- | --- | --- | 
| R1 | Konfiguracioni fajlovi | P11 | Zloupotreba loše konfiguracije | S, T, I, D
| R2 | Blokovi podataka | P21 | Neovlašćeni pristup podacima | I
| R2 |  | P22 | Neovlašćeno upravljanje podacima | I 
| R3 | Alocirani računarski resursi | P31 | Izazivanje nedostupnosti modula | D
| R3 |  | P32 | Zloupotreba alociranih resursa | T
| R4 | Poslovi i zadaci | P41 | Manipulacija poslovima | T, I, D
| R5 | Rezultati | P51 | Manipulacija rezultatima | T 
| R6 | Informacije o statusu | P61 | Lažiranje informacija | T
| R7 | Logovi | P71 | Maliciozno čitanje i pisanje | I, T, R
| R7 | | P72 | Izazivanje nedostupnosti generisanjem logova | D
| R8 | Meta-podaci | P81 | Otmica čvorova | D, I 

_Tebela 2: Prikaz potencijalnih pretnji visokog nivoa u odnosu na kritične resurse_

### Analiza pretnji visokog nivoa

**`R1`**
Konfiguracioni fajlovi *Hadoop* komponenti su vrlo česta meta napadača.

- `P11:`
S obzirom da *Hadoop* poseduje puno komponenti, kao i konfiguracionih fajlova, napadači su svesni te činjenice i gledaju da to iskoriste na maliciozni način. Uvid ili mogućnost izmene konfiguracionih fajlova pružaju velike mogućnosti. Ipak, u praksi se najčešće iskoristi situacija sa podrazumevanim i loše definisanim konfiguracinom fajlovima. 

**`R2`**
Blokovi podataka su omiljeni kritični resurs za napadače. 

- `P21`
Napadači mogu na različite načine zloupotrebiti podatke za koje nemaju prava. Na primer, mogu ukrasti poverljive podatke drugih korisnika i zlouputrebiti ih radi ucene. Takođe ih mogu prodati na crnom tržištu.

- `P22` 
Napadači vrlo često žele da naruše integritet i dostupnost podataka. Na primer, ukoliko bi napadač neovlašćeno čitao podatke, možda mu to ne bi bilo dovoljno za adekvatnu ucenu žrtve. Već bi šifrovanje ili kopiranje pa brisanje takvih podataka bilo efektivnije. Ukoliko bi napadač bio angažovan od strane malicioznog partnera, upravljanjem poverljivim podacima bi uspeo da izmeni ugovore od značaja.  

**`R3`**
Alocirani računarski resursi: RAM, CPU i stalna memorija.

- `P31` Ciljano zauzimanje što veće količine resursa kako bi se izazvala nedostupnost modula čime se negativno utiče na reputaciju poslovnog entiteta.

- `P32` Upotreba alociranih resursa za ispunjenje malicioznih aktivnosti. Napadači žele da alocirane resurse koriste za svoje maliciozne radnje, umesto za osnovnu namenu.

**`R4`**
Poslovi i zadaci izazivaju alociranje resursa potrebnih za obradu podataka. Iz blokova podataka se prvenstveno vrši čitanje, a zatim i pisanje. Poslovi su interesantna meta, jer njihovo kreiranje inicira alociranje resursa. 

- `P41` Napadači najčešće kradu ili podmeću poslove. Krađom poslova se neovlašćeno čitaju podaci ili koriste tuđi resursi. Podmetanjem poslova se zloupotrebljavaju resursi klastera. Pristup osetljivim podacima pruža različite mogućnosti zloupotrebe protiv vlasnika podataka. Alocirani resursi bivaju iskorišteni za maliciozne radnje. Podmetanjem poslova se čak može izazvati i nedostupnost modula.

**`R5`**
Rezultati izračunavanja su interesantni sa aspekta bezbednosti, jer se *Hadoop* moduli koriste i za obradu podataka. Neretko, rezultat obrade podataka predstavlja znanje koje služi za donošenje poslovnih odluka.

- `P51` 
Napadač može na perfidan način manipulisati rezultatima, što za posledicu ima loše upravljanje poslovnim entitetom. Integritet podataka je narušen realizacijom ovakve pretnje. 


**`R6`** Informacije o statusu

- `P61` Lažiranje informacija kako bi se modul doveo u nedostupno stanje ili uticalo negativno na njegove performanse zarad realizacije procesa napadača.

**`R7`** 
Logovi poseduje značajne informacije o radu modula i neretko obiluju osetljivim podacima. Ova vrsta resursa je korisna napadaču iz više razloga:
* Podmetanje i izmena podataka.
* Krađa logova.
* Neovlašćeno čitanje logova.
* Uvid u mehanizme i arhitekturu modula. 
* Otkrivanje propusta i osetljivih podataka.

Prepoznate pretnje visokog nivoa su:
- `P71`  Napadač nakon što je izvršio maliciozne radnje može poželeti da prikrije svoje tragove. Sem prikrivanja može biti korisno i menjanje podataka kako bi se izvršilo podmetanje i kako bi se neko drugi okrivio. Ukoliko napadač planira da realizuje neke kompleksnije pretnje vrlo verovatno će se zainteresovati za analizu logova. Logovi će mu obezbediti dublje razumevanje modula, kao i potencijalne bezbednosne propuste. 

- `P72` Postoje slučajevi i kada napadač poznavajući mehanizme generisanja logova može inicirati kreiranje velike količine logova. Posledica ove pretnje je nedostupnost modula.

**`R8`** 
Meta-podaci su neophodni podaci za adekvatno upravljanje podređenim čvorovima.

- `P81` Ako napadač ostvari pristup ovoj vrsti podataka, vrlo jednostavno može izvršiti otmicu čvorova.  Preuzimanjem kontrole nad čvorovima, moguće ih je iskoristiti za realizaciju malicioznih procesa.

U nastavku slede razrađena stabla napada, analize odabranih napada kao i predložene mitigacije za dve pretnje visokog nivoa:
1. [Direktorijum pretnje `P41`](https://github.com/Vasilijez/apache-hadoop-threat-modeling/tree/vasilije/pretnja_P41)
2. [Direktorijum...](https://github.com/Vasilijez/apache-hadoop-threat-modeling/tree/main/model)

## Reference

<a id="[1]"></a>
[1] [Korišćena terminologija u ovom istraživačkom radu](https://github.com/Luburic/zoss-model-pretnji/blob/main/modeli/terminologija.md) _(Autor: Nikola Luburić, Pristupano: _13. decembra, 2024_)_

<a id="[2]"></a>
[2] [Introduction to Hadoop](https://www.geeksforgeeks.org/hadoop-an-introduction) _(Autor: Geeks for Geeks, Pristupano: _1. juna, 2025_)_

<a id="[3]"></a>
[3] [Apache Hadoop 3.4.1 - Apache Hadoop YARN](https://hadoop.apache.org/docs/current/hadoop-yarn/hadoop-yarn-site/YARN.html) _(Autor: Apache Software Foundation, Pristupano: _4. juna, 2025_)_

<a id="[4]"></a>
[4] [Apache Hadoop 3.4.1 - HDFS Architecture](https://hadoop.apache.org/docs/current/hadoop-project-dist/hadoop-hdfs/HdfsDesign.html) _(Autor: Apache Software Foundation, Pristupano: _4. juna, 2025_)_