<a id="referentna_arhitektura"></a>
# Referentna arhitektura
Ovo je referentni nezaštićeni _Hadoop_ klaster koji je postavljen od strane osobe sa osnovnim znanjima po pitanju bezbednosti. Dijagram se dirketno oslanja na prethodno razrađene dijagrame tokova podataka, s tim da je ovde fokus na čvorovima klastera. Potrebno je uvesti određenu referentnu arhitekturu kako bi se na lakši način ispratile analize, napadi i mitigacije u odnosu na posmatrane pretnje. Konkretan čvor može predstavljati zaseban server, pri čemu svi čvorovi klastera međusobno komuniciraju. Pretpostavka je da su svi čvorovi pokrenuti na operativnom sistemom _Linux_ distribucije , jer se zbog prilagođenosti i podrške takav izbor dominantno sreće u praksi [[2]](#[2]). Kod nezaštićenog klastera korisnik može komunicirati sa svim čvorovima, bilo kroz nezaštićene javne servise ili direktno putem terminal sesije odnosno _SSH_ sesije u kombinaciji sa _Hadoop_ klijent interfejsom. S obzirom da je reč o distribuiranom sistemu, konfiguracije kao i korisnici su redudantno prisutni na svim čvorovima. [[3]](#[3]) Od korisnika, za sada, je potrebno istaći _hdfs_ i _yarn_ koji su ekvivalent _root_ korisniku u _Hadoop_ modulu.

![Referentna arhitektura](./Referentna_arhitektura.svg)

_Slika 1: Komunikacija korisnika sa Hadoop klasterom_

Za referentni klaster uzima se osnovni model bez primene naprednih bezbednosnih mehanizama. Podrazumeva se korišćenje standardno definisane kontrole pristupa _Hadoop_ klastera, pri čemu korisnik ili dobija potpun pristup klasteru ili ga nema uopšte [[4]](#[4]). Na taj način kontrola pristupa se praktično svodi na nivo čvora koji učestvuje u klasteru. Ovakav pristup nije neuobičajen, već se često sreće u praksi, s obzirom na to da se klasteri najčešće podižu u tzv. "bezbednim okruženjima" [[5]](#[5]).

# Stablo napada
Sledeće stablo napada oslikava analizu pretnje visokog nivoa _Manipulacija poslovima (P41)_, koja je prepoznata egzistencijom kritičnog resursa _Poslovi i zadaci (R4)_. 
<a id="slika_2"></a>

![Stablo napada](./Stablo_napada.svg)

_Slika 2: Stablo napada razvijeno u odnosu na pretnju visokog nivoa Manipulacija poslovima (P41)_

Par napomena koje su uvedene radi preglednosti dijagrama:
* Pretnje su povezane samo sa bezbednosnim kontrolama koje predstavljaju dovoljan uslov za njihovu efikasnu zaštitu.
* Keberos kao bezbednosna kontrola se praktično kod svih napada preporučuje, pa je izostavljena. Smatra se da automatski podrazumeva i autorizaciju, ne samo autentifikaciju.
* Trivijalne bezbednosne kontrole, poput ažuriranja verzija zavisnosti, se podrazumevaju. 


U nastavku su predstavljeni odabrani napadi. Oni su definisani tako da što jasnije grupišu klase napada. U skladu sa procenjenim rizikom, izdvojeni napadi predstavljaju najučestalije realizacije pretnji u kontekstu poslova na nivou _YARN_ komponente [[6]](#[6]).

<a id="A4111"></a>
# A4111. Napad na ranjive pristupne tačke _YARN_ komponente

Ovaj napad se pre svega ogleda u načinu funkcionisanja _YARN_ komponentne. Glavni cilj _YARN_ komponente je omogućiti distribuirano procesuiranje najrazličitijih tipova aplikacija bez potrebe za dubljim znanjima. Dakle, isporučiti aplikaciju kroz zahtev i dobiti rezultate procesuiranja. Pošto je moguće uputiti javni zahev za aplikacijom proizvoljnog tipa, a _Hadoop_ klasteri obiluju resursima, to malicioznim korisnicima privlači pažnju.  

Suština napada je plasiranje _malware_ aplikacija kroz eksploataciju ranjivosti pristupnih tačaka.

U _YARN_ komponenti pristupne tačke mogu biti:
1. Pristup putem sesije u terminalu.
2. Pristup putem javno dostupnih _REST API_ servisa.
3. Pristup putem _Web UI_ servisa (nerelevantan, jer ne omogućava kreiranje aplikacija).

Reč je o istoj klasi napada, bez obzira na tip pristupne tačke. Zastupljenost napada je veća kod _REST API_ servisa jer je i površina za napad veća. 

__Sesija u terminalu__

U ovom slučaju reč je o manje verovatnom obliku napada, jer je napadač osoba koja je najčešće prethodno ovlašćena za upotrebu servisa. Ipak, bez obzira, dokle god su pristupne tačke ranjive, moguće je izvršiti napad. 

__REST API servis__

_YARN_ komponenta je javno dostupna preko _ResourceManager_ čvora. Zbog nedostatka autentifikacije napad je moguć čak i uz omogućenu autorizaciju. Da bi se napad sprečio potrebno je implementirati napredne bezbednosne mehanizme.

__Problematika autentifikacije__

S obzirom da _Hadoop_ modul nema internu podršku autentifikaciji, već samo autorizaciji, napadač se vrlo lako može lažno predstaviti. 
Ako _Hadoop_ modul nema javno dostupne pristupne tačke, tada se razmatra slučaj lokalnih korisnika na operativnim sistemima. Lokalni korisnik se prijavljuje na konkretan čvor sa svojim kredencijalima. _Hadoop_ modul će u promenljivu `HADOOP_USER_NAME` smestiti korisničko ime ulogovanog korisnika. Korisnik na trivijalan način može izmeniti promenljivu na vrednost `hdfs`, `yarn` ili bilo čije korisničko ime (npr. `alice`). 
``` sh
export HADOOP_USER_NAME=alice
hadoop fs -ls /data/financial_data
```
Za slučaj kada _Hadoop_ modul ima javno dostupne pristupne tačke, dovoljno je proslediti proizvoljnu vrednost korisničkog imena (npr. `admin`) kao upitni parametar _HTTP_ zahteva. 
``` sh
curl -X POST http://resource-manager:8088/ws/v1/cluster/apps/new-application?user.name=admin
```
Zaključuje se da je nepostojećom autentifikacijom obesmišljena autorizacija.

__Sinergija faktora__

Sledeći faktori sinergetski utiču na pojavu ovog napada:
- Istorijski bezbednost nije bila fokus _Hadoop_ modula. Podrazumevalo se bezbedno okruženje.
- Podrazumevani režim _Hadoop_ modula (_Simple Authentication_) je nebezbedan.
- _YARN REST API_ i _Web UI_ servisi su podrazumevano javno dostupni.
- _Hadoop_ modul favorizuje _usability_.
- Izuzetna kompleksnost implementacija komponente za autentifikaciju - _Kerberos_ [[7]](#[7])[[8]](#[8]).
- Korisnik se može lažno predstaviti (_spoofing_).
- Ako nema autentifikacije tada nema ni autorizacije.
- Aplikacije mogu biti različitog tipa. Teško utvrditi semantiku.
- Aplikacije (kontejneri) se pokreću od strane _yarn_ korisnika.
- Dopušten izlazni saobraćaj prema bilo kome.
- Praktično direktno obraćanje čvorovima.
- Angažovanje nestručnog osoblja (junior administrator).
- Nije potrebno naročito tehničko znanje (mnoštvo napadača).
- Velika površina za napad.

To su ključni razlozi zašto _YARN_ pristupne tačke, pre svega javno dostupne, postaju tako lako ranjive, i zašto ovaj napad predstavlja izbor broj jedan u _Hadoop_ klasterima. Stoga je reč o trivijalnoj, ali kritičnoj ranjivosti.

__Zanimljivosti__

Ako se razmatra napad na javno dostupne pristupne tačke, sa pretpostavljenim [klasterom](referentna_arhitektura), onda se mogu pronaći sledeće zanimljivosti. Poznato je da je u pitanju najzastupljenija klasa napada u _Hadoop_ klasterima, pri čemu se svakog momenta izvrši 300 000 pokušaja realizacije. Svi javno dostupni _Hadoop_ klasteri bivaju aktivno traženi od strane specijalizovanih pretraživača kao što su _Shodan_ ili _Fofa_ [[6]](#[6]). Pitanje je vremena kada će biti pronađeni i napadnuti.

Kao što se može primetiti pregledom stabla napada na [slici 2](#slika_2), realizacijom ovog napada ostvaruje se događaj pokretanje maliciozne aplikacije. Cilj napadača će biti predodređen tipom maliciozne aplikacije. U praksi se najčešće sreću _botnet_, _crypto mining_ i _ransomware_ aplikacije, pri čemu gotovo uvek dolazi i do krađe podataka [[9]](#[9]). Da bi opis ove klase napada bio zanimljiviji i realističniji, fokus će biti na pokretanju _crypto mining_ aplikacije. Uz napomenu da je krađa podataka daleko najozbiljnija pretnja po jedan _Hadoop_ klaster, a osnovni cilj napadača često se širi, obuhvatajući sve kritične resurse i servise kojima ima pristup, uz mogućnost pivotiranja [[10]](#[10])[[11]](#[11]). Pokretanje malicioznih aplikacija je kritična pretnja kojom se u zavisnosti od tipa aplikacije može narušiti bilo koje bezbednosno svojstvo resursa ili servisa. Rizik za realizacijom ove pretnje je kritičan s obzirom na visok negativan uticaj pretnje i visoku verovatnoću izvršavanja.


# Reference

<a id="[1]"></a>
[1] [Korišćena terminologija u ovom istraživačkom radu](https://github.com/Luburic/zoss-model-pretnji/blob/main/modeli/terminologija.md) _(Autor: Nikola Luburić, Pristupano: _13. decembra, 2024_)_

<a id="[2]"></a>
[2] [Which is the best operating system to run Hadoop?](https://www.researchgate.net/post/Which_is_the_best_operating_system_to_run_Hadoop) _(Autor: Dhananjaya Gm, Pristupano: _25. juna, 2025_)_

<a id="[3]"></a>
[3] [Hadoop Security: Protecting your big data platform - Provisioning of Hadoop Users](https://www.oreilly.com/library/view/hadoop-security/9781491900970/) _(Autor: Ben Spivey, Joey Echeverria, Izdato: _01. jula, 2015_)_

<a id="[4]"></a>
[4] [Hadoop Security: Protecting your big data platform - Knjiga: Why Kerberos?](https://www.oreilly.com/library/view/hadoop-security/9781491900970/) _(Autor: Ben Spivey, Joey Echeverria, Izdato: _01. jula, 2015_)_

<a id="[5]"></a>
[5] [Hadoop Security: Protecting your big data platform - Hadoop Security: A Brief History](https://www.oreilly.com/library/view/hadoop-security/9781491900970/) _(Autor: Ben Spivey, Joey Echeverria, Izdato: _01. jula, 2015_)_

<a id="[6]"></a>
[6] [Hadoop YARN: An Assessment of the Attack Surface and Its Exploits](https://www.radware.com/blog/security/hadoop-yarn-an-assessment-of-the-attack-surface-and-its-exploits/) _(Autor: Pascal Geenens, Pristupano: _1. jula, 2025_)_

<a id="[7]"></a>
[7] [What are the challenges of using Kerberos for Big Data applications?](https://www.linkedin.com/advice/1/what-benefits-challenges-using-kerberos-securing-big-data) _(Autor: Ujjwal Sontakke Jain, Pristupano: _25. jula, 2025_)_

<a id="[8]"></a>
[8] [Taming the Three-headed Beast: Understanding Kerberos for Trouble-shooting Hadoop Security](https://medium.com/@blackvvine/taming-the-three-headed-beast-understanding-kerberos-for-trouble-shooting-hadoop-security-12f6c152fe97) _(Autor: Iman Akbari, Pristupano: _25. jula, 2025_)_

<a id="[9]"></a>
[9] [Apache Applications Targeted by Stealthy Attacker](https://www.aquasec.com/blog/threat-alert-apache-applications-targeted-by-stealthy-attacker/) _(Autor: Nitzan Yaakov, Asaf Eitani, Pristupano: _25. jula, 2025_)_

<a id="[10]"></a>
[10] [Threat Actors Exploit Misconfigured Apache Hadoop YARN](https://www.trendmicro.com/en_fi/research/21/g/threat-actors-exploit-misconfigured-apache-hadoop-yarn.html) _(Autor: Alfredo Oliveira, David Fiser, Pristupano: _25. jula, 2025_)_

<a id="[11]"></a>
[11] [Pivot](https://csrc.nist.gov/glossary/term/pivot) _(Autor: National Institute of Standards and Technology, Pristupano: _25. jula, 2025_)_
