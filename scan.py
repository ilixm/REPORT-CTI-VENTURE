import json
import os

# Les réglages de la formule
COEF_CVSS = 0.30
COEF_EPSS = 0.30
BONUS_KEV = 2.0
MAX_POINTS = 11.5
FACTEUR_MITIGATION = 0.3

# Les malus selon le compte nécessaire pour exploiter la faille
MALUS_PREREQUIS = {
    "none": 0.0,
    "user": -0.5,
    "admin": -1.0,
}

# Les délais de correction par priorité
SLA = {
    "P0": "< 4 h à 24 h",
    "P1": "< 72 h",
    "P2": "< 14 jours",
    "P3": "< 30 à 60 jours",
    "P4": "> 60 jours / accepté",
}

# Les couleurs du terminal (codes ANSI)
COULEURS = {
    "P0": "\033[97;41m",        # blanc sur fond rouge
    "P1": "\033[30;48;5;208m",  # noir sur fond orange
    "P2": "\033[30;43m",        # noir sur fond jaune
    "P3": "\033[97;44m",        # blanc sur fond bleu
    "P4": "\033[30;47m",        # noir sur fond gris
}
GRAS = "\033[1m"
RESET = "\033[0m"

# L'ordre des priorités, de la plus urgente à la moins urgente
ORDRE = ["P0", "P1", "P2", "P3", "P4"]

# Les actifs de Venture Group
ASSETS = {
    "ASSET-01": {"nom": "SAP S/4HANA",     "exposition": 0.0, "criticite": 1.5, "internet": False},
    "ASSET-02": {"nom": "Ivanti VPN",      "exposition": 2.0, "criticite": 1.0, "internet": True},
    "ASSET-03": {"nom": "Confluence",      "exposition": 0.5, "criticite": 0.5, "internet": False},
    "ASSET-04": {"nom": "MOVEit Transfer", "exposition": 1.0, "criticite": 1.0, "internet": False},
    "ASSET-05": {"nom": "Active Directory","exposition": 0.5, "criticite": 1.5, "internet": False},
}


# Fonction de calcul
def calcul_score(cve):
    asset = ASSETS[cve["asset"]]

    points_cvss = cve["cvss"] * COEF_CVSS
    points_epss = cve["epss"] * 10 * COEF_EPSS

    if cve["kev"]:
        points_kev = BONUS_KEV
    else:
        points_kev = 0

    # Malus prérequis, annulé si la CVE est chaînée à une autre
    malus = MALUS_PREREQUIS[cve["preconditions"]]
    if cve["chain_with"]:
        malus = 0

    total = points_cvss + points_epss + points_kev + asset["exposition"] + asset["criticite"] + malus

    # Mitigation : composant vulnérable désactivé chez nous
    if cve["mitigated"]:
        total = total * FACTEUR_MITIGATION

    score = total / MAX_POINTS * 10
    return round(score, 2)


# Fonction de classement
def calcul_priorite(score):
    if score >= 9.0:
        return "P0"
    elif score >= 6.5:
        return "P1"
    elif score >= 3.0:
        return "P2"
    elif score >= 2.5:
        return "P3"
    else:
        return "P4"


# Règles de plancher (garde-fous)
def appliquer_plancher(cve, priorite):
    asset = ASSETS[cve["asset"]]

    if cve["mitigated"]:
        return priorite
    if cve["kev"] and asset["internet"]:
        return "P0"
    if cve["kev"] and priorite in ["P2", "P3", "P4"]:
        return "P1"
    return priorite


# Clé de tri : d'abord la priorité, puis le score le plus haut
def cle_de_tri(resultat):
    return (ORDRE.index(resultat["priorite"]), -resultat["score"])


# Affichage du tableau en couleur
def afficher_tableau(resultats):
    os.system("")  # active les couleurs dans le terminal Windows

    entete = f"{'#':>2}  {'Prio':^6}  {'CVE':<15} {'Actif':<17} {'CVSS':>4}  {'EPSS':>7}  {'KEV':^3}  {'Score':>5}  SLA"
    print()
    print(GRAS + "AGENDA DE REMÉDIATION - VENTURE GROUP" + RESET)
    print(GRAS + entete + RESET)
    print("-" * len(entete))

    for rang, r in enumerate(resultats, start=1):
        couleur = COULEURS[r["priorite"]]
        prio = couleur + f"{r['priorite']:^6}" + RESET
        kev = "OUI" if r["kev"] else "NON"
        print(f"{rang:>2}  {prio}  {r['cve']:<15} {r['actif']:<17} {r['cvss']:>4}  "
              f"{r['epss'] * 100:6.2f}%  {kev:^3}  {r['score']:>5.2f}  {r['sla']}")

    print("-" * len(entete))

    # Petit résumé : combien de CVE par priorité
    resume = ""
    for p in ORDRE:
        nombre = 0
        for r in resultats:
            if r["priorite"] == p:
                nombre = nombre + 1
        resume = resume + COULEURS[p] + f" {p} : {nombre} " + RESET + "  "
    print(resume)
    print()


# Lire les CVE
with open("cves.json", encoding="utf-8") as fichier:
    cves = json.load(fichier)

# Calculer le score et la priorité de TOUTES les CVE
resultats = []
for cve in cves:
    score = calcul_score(cve)
    priorite = calcul_priorite(score)
    priorite = appliquer_plancher(cve, priorite)

    resultats.append({
        "cve": cve["cve"],
        "actif": ASSETS[cve["asset"]]["nom"],
        "cvss": cve["cvss"],
        "epss": cve["epss"],
        "kev": cve["kev"],
        "score": score,
        "priorite": priorite,
        "sla": SLA[priorite],
    })

# Trier : P0 en haut
resultats.sort(key=cle_de_tri)

# Afficher le tableau
afficher_tableau(resultats)
