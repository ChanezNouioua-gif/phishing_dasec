# reindex_full.py — Intégration complète locale (MITRE + OpenPhish + URLhaus)
import chromadb
import json
import os
import hashlib
import re
from sentence_transformers import SentenceTransformer
from collections import defaultdict
from datetime import datetime

VECTORSTORE_DIR = "/app/data/vectorstore"
IOC_CACHE_DIR = "/app/data/ioc_cache"

print("Chargement embedder...")
embedder = SentenceTransformer("all-MiniLM-L6-v2")
chroma_client = chromadb.PersistentClient(path=VECTORSTORE_DIR)

def embed_fn(texts):
    return embedder.encode(texts).tolist()

# ==============================================================
# PARTIE 1 — MITRE ATT&CK STIX COMPLET
# ==============================================================

print("\nChargement du fichier local MITRE ATT&CK Complet (47MB)...")
LOCAL_STIX_PATH = "/app/data/enterprise-attack.json"

with open(LOCAL_STIX_PATH, "r", encoding="utf-8") as f:
    objects = json.load(f)["objects"]
print(f"-> {len(objects)} objets STIX chargés.")

# Extraction des relations et dictionnaires de mapping
stix_id_to_obj = {obj["id"]: obj for obj in objects}
stix_id_to_name = {obj["id"]: obj.get("name","") for obj in objects}
stix_id_to_attck = {}
relations = defaultdict(list)
tech_id_to_data = {}

for obj in objects:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            stix_id_to_attck[obj["id"]] = ref.get("external_id","")
            break

for obj in objects:
    if obj.get("type") == "relationship":
        src = obj.get("source_ref","")
        tgt = obj.get("target_ref","")
        rel = obj.get("relationship_type","")
        if src and tgt and rel:
            relations[src].append((tgt, rel))

# Nettoyage des anciennes collections
for col_name in ["mitre_techniques", "mitre_apt_groups", "threat_intel", "live_ioc_feeds"]:
    try:
        chroma_client.delete_collection(col_name)
        print(f"Nettoyage collection: {col_name}")
    except Exception:
        pass

# --- Indexation des Techniques ---
col_techniques = chroma_client.create_collection(name="mitre_techniques", metadata={"hnsw:space": "cosine"})
techniques = []

for obj in objects:
    if obj.get("type") != "attack-pattern": continue
    if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False): continue
    tech_id = stix_id_to_attck.get(obj["id"],"")
    if not tech_id: continue

    platforms = ", ".join(obj.get("x_mitre_platforms",[]))
    tactics = ", ".join([p["phase_name"].replace("-"," ").title() for p in obj.get("kill_chain_phases",[]) if p.get("kill_chain_name") == "mitre-attack"])
    name = obj.get("name","")
    description = obj.get("description","")[:600]
    detection = obj.get("x_mitre_detection","")[:300]

    doc_text = f"Technique: {tech_id} {name}. Tactics: {tactics}. Platforms: {platforms}. {description} Detection: {detection}"
    data = {"id": tech_id, "stix_id": obj["id"], "name": name, "tactics": tactics, "platforms": platforms, "doc_text": doc_text}
    techniques.append(data)
    tech_id_to_data[tech_id] = data

batch_size = 128
for i in range(0, len(techniques), batch_size):
    batch = techniques[i:i+batch_size]
    col_techniques.add(
        documents = [t["doc_text"] for t in batch],
        embeddings = embed_fn([t["doc_text"] for t in batch]),
        metadatas = [{"tech_id": t["id"], "name": t["name"], "tactics": t["tactics"], "platforms": t["platforms"]} for t in batch],
        ids = [t["id"] for t in batch]
    )
print(f"-> mitre_techniques: {col_techniques.count()} techniques réelles indexées.")

# --- Indexation des Groupes APT ---
col_apt = chroma_client.create_collection(name="mitre_apt_groups", metadata={"hnsw:space": "cosine"})
apt_groups = []

for obj in objects:
    if obj.get("type") != "intrusion-set": continue
    if obj.get("revoked", False): continue
    group_id = stix_id_to_attck.get(obj["id"],"")
    if not group_id: continue

    name = obj.get("name","")
    aliases = ", ".join(obj.get("aliases",[name]))
    desc = obj.get("description","")[:500]
    doc_text = f"APT Group: {group_id} {name}. Aliases: {aliases}. {desc}"
    apt_groups.append({"id": group_id, "stix_id": obj["id"], "name": name, "aliases": aliases, "description": desc, "doc_text": doc_text})

if apt_groups:
    col_apt.add(
        documents = [g["doc_text"] for g in apt_groups],
        embeddings = embed_fn([g["doc_text"] for g in apt_groups]),
        metadatas = [{"group_id":g["id"],"name":g["name"],"aliases":g["aliases"]} for g in apt_groups],
        ids = [g["id"] for g in apt_groups]
    )
print(f"-> mitre_apt_groups: {col_apt.count()} groupes APT réels indexés.")

# --- Indexation Threat Intel Enrichie ---
col_ti = chroma_client.create_collection(name="threat_intel", metadata={"hnsw:space": "cosine"})
threat_intel_docs = []

print("Génération des profils de Threat Intel croisés...")
for group in apt_groups:
    stix_id = group["stix_id"]
    used_techniques = []

    for (target_ref, rel_type) in relations.get(stix_id, []):
        if rel_type != "uses": continue
        target_obj = stix_id_to_obj.get(target_ref,{})
        if target_obj.get("type") != "attack-pattern": continue
        attck_id = stix_id_to_attck.get(target_ref,"")
        tech_name = stix_id_to_name.get(target_ref,"")
        if not attck_id: continue
        tech_data = tech_id_to_data.get(attck_id,{})
        used_techniques.append({"id": attck_id, "name": tech_name, "tactics": tech_data.get("tactics","")})

    if len(used_techniques) < 2: continue

    phishing_techs = [t for t in used_techniques if any(kw in t["name"].lower() for kw in ["phish","spearphish","credential","link","attachment","email","lure"])]
    is_email_threat = len(phishing_techs) > 0
    tech_lines = "\n".join([f"  - {t['id']} {t['name']}" for t in used_techniques[:15]])
    
    doc_text = f"APT Profile: {group['id']} {group['name']}\nAliases: {group['aliases']}\nEmail threat: {'yes' if is_email_threat else 'no'}\nTotal techniques: {len(used_techniques)}\nDescription: {group['description'][:300]}\nTTPs:\n{tech_lines}"

    threat_intel_docs.append({
        "id": f"profile_{group['id']}",
        "campaign": f"{group['name']} TTPs Profile",
        "actor": group["name"],
        "group_id": group["id"],
        "is_email_threat": str(is_email_threat),
        "doc_text": doc_text,
    })

for i in range(0, len(threat_intel_docs), batch_size):
    batch = threat_intel_docs[i:i+batch_size]
    col_ti.add(
        documents = [d["doc_text"] for d in batch],
        embeddings = embed_fn([d["doc_text"] for d in batch]),
        metadatas = [{"campaign":d["campaign"],"actor":d["actor"],"is_email_threat":d["is_email_threat"]} for d in batch],
        ids = [d["id"] for d in batch]
    )
print(f"-> threat_intel: {col_ti.count()} profils d'acteurs complets générés.")


# ==============================================================
# PARTIE 2 — FLUX IOC LIVE REGROUPÉS (OpenPhish + URLhaus)
# ==============================================================

print("\nTraitement des flux d'IOCs (OpenPhish + URLhaus)...")
raw_urls = []


# Extraction OpenPhish
LOCAL_OP = "/app/data/ioc_cache/openphish.txt"
if os.path.exists(LOCAL_OP):
    with open(LOCAL_OP, "r", encoding="utf-8", errors="replace") as f:
        raw_urls.extend([l.strip() for l in f.readlines() if l.strip() and not l.startswith("#")])

# Extraction URLhaus
LOCAL_UH = "/app/data/ioc_cache/urlhaus.abuse.ch.txt"
if os.path.exists(LOCAL_UH):
    with open(LOCAL_UH, "r", encoding="utf-8", errors="replace") as f:
        raw_urls.extend([l.strip() for l in f.readlines() if l.strip() and not l.startswith("#")])



# Déduplication
unique_urls = list(set(raw_urls))
print(f"-> {len(unique_urls)} URLs malveillantes uniques collectées.")

# Filtration et limitation
SUSPICIOUS_KEYWORDS = ["login", "signin", "verify", "account", "secure", "auth", "paypal", "microsoft", "google", "office", "update"]
priority_urls = [u for u in unique_urls if any(kw in u.lower() for kw in SUSPICIOUS_KEYWORDS)]
other_urls = [u for u in unique_urls if u not in priority_urls]

urls_to_index = (priority_urls + other_urls)[:2500]

col_live = chroma_client.create_collection(name="live_ioc_feeds", metadata={"hnsw:space": "cosine"})
docs_live = []

for url in urls_to_index:
    url_low = url.lower()
    m = re.search(r"(?:https?://)?(?:www\.)?([^/\s]+)", url_low)
    domain = m.group(1) if m else "unknown"
    
    doc_text = f"IOC Phishing Threat URL: {url}. Target Domain: {domain}."
    uid = hashlib.md5(url.encode()).hexdigest()[:16]
    docs_live.append({"id": uid, "url": url, "domain": domain, "doc_text": doc_text})

for i in range(0, len(docs_live), batch_size):
    batch = docs_live[i:i+batch_size]
    col_live.add(
        documents = [d["doc_text"] for d in batch],
        embeddings = embed_fn([d["doc_text"] for d in batch]),
        metadatas = [{"url": d["url"], "domain": d["domain"], "source": "LiveFeeds"} for d in batch],
        ids = [d["id"] for d in batch]
    )
print(f"-> live_ioc_feeds: {col_live.count()} URLs de menaces actives indexées.")

# ==============================================================
# RÉSUMÉ DU SUCCÈS
# ==============================================================
print("\n" + "="*55)
print("RÉSUMÉ FINAL DE LA BASE VECTORIELLE")
print("="*55)
for col in chroma_client.list_collections():
    print(f"  [Collection] {col.name}: {col.count()} entrées actives")

print("\nBase de connaissances RAG réindexée avec brio.")