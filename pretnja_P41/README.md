<a id="referentna_arhitektura"></a>
# Referentna arhitektura
Ovo je referentni nezaštićeni _Hadoop_ klaster koji je postavljen od strane osobe sa osnovnim znanjima po pitanju bezbednosti. Dijagram se dirketno oslanja na prethodno razrađene dijagrame tokova podataka, s tim da je ovde fokus na čvorovima klastera. Potrebno je uvesti određenu referentnu arhitekturu kako bi se na lakši način ispratile analize, napadi i mitigacije u odnosu na posmatrane pretnje. Konkretan čvor može predstavljati zaseban server, pri čemu svi čvorovi klastera međusobno komuniciraju. Pretpostavka je da su svi čvorovi pokrenuti na operativnom sistemom _Linux_ distribucije , jer se zbog prilagođenosti i podrške takav izbor dominantno sreće u praksi [[2]](#[2]). Kod nezaštićenog klastera korisnik može komunicirati sa svim čvorovima, bilo kroz nezaštićene javne servise ili direktno putem terminal sesije odnosno _SSH_ sesije u kombinaciji sa _Hadoop_ klijent interfejsom. S obzirom da je reč o distribuiranom sistemu, konfiguracije kao i korisnici su redudantno prisutni na svim čvorovima. [[3]](#[3]) Od korisnika, za sada, je potrebno istaći _hdfs_ i _yarn_ koji su ekvivalent _root_ korisniku u _Hadoop_ modulu.

![Referentna arhitektura](./Referentna_arhitektura.svg)

_Slika 1: Komunikacija korisnika sa Hadoop klasterom_

Za referentni klaster uzima se osnovni model bez primene naprednih bezbednosnih mehanizama. Podrazumeva se korišćenje standardno definisane kontrole pristupa _Hadoop_ klastera, pri čemu korisnik ili dobija potpun pristup klasteru ili ga nema uopšte [[4]](#[4]). Na taj način kontrola pristupa se praktično svodi na nivo čvora koji učestvuje u klasteru. Ovakav pristup nije neuobičajen, već se često sreće u praksi, s obzirom na to da se klasteri najčešće podižu u tzv. "bezbednim okruženjima" [[5]](#[5]).
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

