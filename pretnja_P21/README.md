# Korišćeni _Hadoop_ klaster

Za analizu napada iskorišćen je nezaštićen _Hadoop_ klaster [[2]]. Sa bezbedonosnog aspekta, klaster ima samo osnovne elemente. U praksi se najčešće koristi operativni sistem _Linux_ za pokretanje čvorova [[3]]. Kada je klaster nezaštićen, korisnik može da komunicira sa bilo kojim čvorom, putem nezaštićenih javih servisa ili putem terminal sesije direktno pomoću _SSH_ i _Hadoop_ klijent interfejsom. Arhitektura na visokom nivou apstrakcije je data na slici 1. Kod distribuiranih sistema su konfiguracije i korisnici redudantno prisutni na svim čvorovima [[4]]. U ovom delu najveći fokus je stavljen na _DataNode_-ove HDFS komponente.

![Apstrakovana arhitektura komunikacije sa _Hadoop_ klasterom](./Arhitektura.png)

_Slika 1: Apstrakovana arhitektura komunikacije sa Hadoop klasterom_

_Hadoop_ klaster korišćen u ovom delu nema implementirane napredne bezbedosnosne mehanizme. Standardno definisane kontrole pristupa _Hadoop_ klasteru podrazumevaju da korisnik ili dobija potpun pristup klasteru ili ga nema uopšte [[5]]. Na taj način, kontrola pristupa je svedena na nivo čvora koji učestvuje u klasteru. Ovakav pristup je čest u praksi jer se klastiri podižu u "bezbednim okruženjima" [[6]].

# Stablo napada

Stablo napada na slici 2, predstavlja analizu pretnje visokog nivoa _Neovlašćeni pristup podacima (P21)_. Pretnja je detektovana ugroženim kritičnim resursom _Blokovi podataka (R2)_. 

![Stablo napada](./StabloPretnji.jpg)

_Slika 2: Stablo napada razvijeno za pretnju visokog nivoa Neovlašćen pristup podacima (P21)_

U nastavku je dat kratak opis pretnji niskog nivoa, konkretnih napada i mitigacija relevantnih za njih. Takođe, u tabeli 1 je prikazana svaka pretnja niskog nivoa zajedno sa odgovarajućim _STRIDE_ tipom.

P211: Neovlašćeno čitanje blokova (eksfiltracija blokova)
- P2111: Direktan pristup host _FS_ (ili _container mount_)
    - Napadač sa _shell_ / FS pristupom kopira blokove podataka if _/dfs/data/current_.
    - Mitigacije:
        - M2111a: Ograničiti _SSH_ / doker pristup (_least privilage_)
        - M2111b: Ukloni nepotrebne _bind-mount_-ove 
        - M2111v: Koristi _read-only mount_-ove za host _backup_
        - M2111g: Uvođenje autentifikacije (_Kerberos_)
- P2112: _Abuz WebHDFS / HTTP endpoint_ 
    - _WebHDFS_ ili _NameNode UI_ bez autorizacije dozvoljava _`user.name`_ impersonaciju i skidanje blokova.
    - Mitigacije:
        - M2112a: Onemogući ili ograniči _WebHDFS_ ili _firewall_-om dozvoli samo pristup adminu / subnet-u
        - M2112b: Uvođenje autentifikacije (_Kerberos_)
        - M2112v: Uvođenje TLS-a
- P2113: Pasivno prislučkivanje transfera (_MITM / sniffing_)
    - Presretanje _HDFS_ transfera između klijenta i _DataNode_ ako nema _TLS_
    - Mitigacije:
        - M2113a: Omogući _TLS_ za _RPC / HTTP_ (_in-transit encryption_)
        - M2113b: Segmentacija mreže (Privatne _VLAN_-ove / doker _networks_)

P212: Sabotaža / gubitak podataka (brisanje ili _truncate_)
- P2121: Direktno brisanje blokova fajlova na _DataNode_ hostu
    - Ručno brisanje ili preimenovanje fajlova na hostu.
    - Mitigacije:
        - M2121a: Zabrani korisnicima _write_ pristup _DataNode data_ folderu
        - M2121b: _Enforce SELinux / AppArmor_
        - M2121v: Minimalizuj broj onih koji imaju privilegije nad kontejnerima
- P2122: _RPC / ClientProtocol delete_ zahtevi bez autorizacije
    - Slanje _delete / rename_ zahteva _NameNode_-u bez autorizacije.
    - Mitigacije:
        - M2122a: Onemogući neautorizovan _RPC_ pristup (_firewall, ACL_)
        - M2122b: Uvedi _Kerberos_ autorizaciju
        - M2122v: Ograniči _API_ pristup
- P2123: Disk _fill / resource exhaustion_
    - Napadač popuni disk prostor na _DataNode_-u da uzrokuje pad / označavanje _node_-a kao _failed_.
    - Mitigacije:
        - M2123a: Disk _quot_-a
        - M2123b: Disk _usage monitoring_
        - M2123v: Ograničenje za _temp_ direktorijum
        - M2123g: Pravilno odvojeni diskovi za operativno sistem i _HDFS data_

P213: Korupcija blokova (_checksum mismatch / bitflip_)
    - P2131: Namerno modifikovanje _block_ fajlova (_owerwrite / truncate_)
        - Pomoću _write_ pristupa menjamo sadržaj _block_ fajlova (_checksum mismatch_).
        - Mitigacije:
            - M2131a: FIM
            - M2131b: _Read-only snapshot_-ovi
            - M2131v: _Harden host access_
            - M2131g: Dovoljno replikacija (3+) da se može obnoviti iz zdravih replika
- P2132: Enkapsulacija _block_ fajlova (ransomware)
    - Enkapsuliranje lokalnih _block_ fajlova čini podatke nečitljivim.
    - Mitigacije:
        - M2132a: _EDR_ za rano otkrivanje _ransomare_-a
        - M2132b: _Offline / immutable backups_
        - M2132v: _Least-privilege_ kontrole
- P2133: Manipulacija pri transferu (_bitflipping MITM_)
    - Menja se podatak tokom transfera bez da se menja lokalni fajl (teško bez _MITM_).
    - Mitigacije:
        - M2133a: _TLS_ za transfer
        - M2133b: _Integrity checks_ pri prijemu
        - M2133v: _MAC / crypto checks_

P214: Lažno prijavljivanje (_spoofing_) / lažni _block reports_
- P2141: _Spoof_-ovan _DataNode_ šalje lažne _block report_-ove.
    - _Regue node_ tvrdi da poseduje _blok_-ove koje nema ili prijavljuje lažne _block_-ove.
    - Mitigacije:
        - M2141a: Dodavanje autentifikacije _DataNode_ registracije (_cert-based / Kerberos_)
        - M2141b: _Network whitelist_ za _DataNode_-ove
- P2142: _Replay_ starih _block report_-ova / _fsimage_-a
    - Vraćanje starih _report_-ova ili _fsimage_-a za izazivanje _inconsistency_.
    - Mitigacije:
        - M2142a: _Integrity chesks_ za _fsimage_ (_hash / singing_)
        - M2142b: _Secure storage_ za _checkpoint_-e
        - M2142v: _Access control_
- P2143: Registracija lažnog _DataNode_-a (_unregistered / rogue node_)
    - _Rogue node_ se registruje i prihvata _block_ repliciranje.
    - Mitigacije:
        - M2143a: Segmentacija mreže za registraciju _DataNode_-a
        - M2143b: _Whitelist IP_ adresa
        - M2143v: _Mutual TLS_

P215: Forenžičko prikupljanje (_log tampering_)
- P2151: Brisanje / izmena lokalnih _DatNode_ logova
    - Napadač briše ili menja logove da prikrije svoje radnje.
    - Mitigacije:
        - P2151a: Centralizovano _write-once_ logovanje
        - P2151b: _WORM storage_ za _audit_ logove
- P2152: Isključivanje / prekidanje logovanja, uklanjanje _audit sink_-a
    - Prekid logovanja da bi napad ostao neotkriven.
    - Mitigacije:
        - M2152a: Redudantni _log sink_-ovi
        - M2152b: _Log forwarding_ u realnom vremenu
        - M2152v: _DLP_ na log konfiguraciju

P216: Lateralno širenje i eskalacija
- P2161: Eskalacija na hostu (_privilege escalation_, potpuni pristup _block_ fajlovima)
    - Iskorišćenje lokalne ranjivosti da se podignu privilegije.
    - Mitigacije:
        - M2161a: _Hardening host_-a
        - M2161b: Minimalni _kernel surface_
        - M2161v: Redovan _Patching_
        - M2161g: _Sudo hardening_
- P2162: Korišćenje kompromitovanog _DataNode_-a za kompromitovanje drugih _DataNode_-ova (Propagacija)
    - Lateralno širenje kroz mrežu / SSH / konfiguracije.
    - Mitigacije:
        - M2162a: Mikro-segmentacija
        - M2162b: Kontrolisani pristup između _DataNode_-ova
        - M2162v: _Rotate_ sertifikata / ključeva 

| IDP | Pretnja niskog nivoa | _STRIDE_ tip
| ----- | --- | --- | 
| P211 | Neovlašćeno čitanje | _Information disclosure_
| P212 | Sabotaža / gubitak podataka | _Denial of service_
| P213 | Korupcija blokova | _Tampering_
| P214 | Lažno prijavljivanje | _Spoofing_
| P215 | Forenzičko prikupljanje | _Repudiation_
| P216 | Lateralno širenje i eskalacija | _Elevation of privilege_

_Tabela 1: Pretnje niskog nivoa sa odgovarajućim STRIDE tipom_

## Reference

<a id="[1]"></a>
[1] [Korišćena terminologija u ovom istraživačkom radu](https://github.com/Luburic/zoss-model-pretnji/blob/main/modeli/terminologija.md) _(Autor: Nikola Luburić, Pristupano: _13. decembra, 2024_)_

<a id="[2]"></a>
[2] [Korišćeni Hadoop klaster](https://github.com/tmiroslav97/asvsp-architecture) _(Autor: Miroslav Tomic, Pristupano: _10. oktobra, 2025_)_

<a id="[3]"></a>
[3] [Which is the best operating system to run Hadoop?](https://www.researchgate.net/post/Which_is_the_best_operating_system_to_run_Hadoop) _(Autor: Dhananjaya Gm, Pristupano: _25. juna, 2025_)_

<a id="[4]"></a>
[4] [Hadoop Security: Protecting your big data platform - Provisioning of Hadoop Users](https://www.oreilly.com/library/view/hadoop-security/9781491900970/) _(Autor: Ben Spivey, Joey Echeverria, Izdato: _01. jula, 2015_)_

<a id="[5]"></a>
[5] [Hadoop Security: Protecting your big data platform - Knjiga: Why Kerberos?](https://www.oreilly.com/library/view/hadoop-security/9781491900970/) _(Autor: Ben Spivey, Joey Echeverria, Izdato: _01. jula, 2015_)_

<a id="[6]"></a>
[6] [Hadoop Security: Protecting your big data platform - Hadoop Security: A Brief History](https://www.oreilly.com/library/view/hadoop-security/9781491900970/) _(Autor: Ben Spivey, Joey Echeverria, Izdato: _01. jula, 2015_)_