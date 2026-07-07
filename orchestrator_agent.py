import time
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime, timezone


# ──────────────────────────────────────────────────────────────
# Constantes de l'agent
# ──────────────────────────────────────────────────────────────

# Seuils de contradiction entre modules — les seuils de VERDICT (suspect/phishing)
# ne sont plus dupliqués ici : ils sont passés au constructeur d'OrchestratorAgent
# depuis api_v2.py (SCORE_THRESHOLD_SUSPECT / SCORE_THRESHOLD_PHISHING), pour éviter
# la désynchronisation qu'on a eue (0.35/0.65 ici vs 0.40/0.70 dans api_v2.py).
CONTRADICTION_DELTA   = 0.45   # écart score NLP vs URLs au-delà duquel on re-analyse
EARLY_EXIT_THRESHOLD  = 0.88   # score brut suffisamment haut pour court-circuiter le LLM
MAX_REANALYSIS_LOOPS  = 2      # nombre max de re-analyses pour éviter les boucles infinies

# Seuils de verdict par défaut, utilisés seulement si l'appelant n'en fournit pas.
# Doivent normalement être synchronisés avec SCORE_THRESHOLD_SUSPECT/PHISHING de api_v2.py.
DEFAULT_SUSPECT_THRESHOLD  = 0.40
DEFAULT_PHISHING_THRESHOLD = 0.70

# Poids par mode (centralisés ici, plus dans compute_global_score)
# FIX bug#4 : "ti" (VirusTotal/AbuseIPDB) est presque toujours à 0 pour du phishing
# récent/inconnu des bases externes — c'est le cas le plus courant et le plus dangereux.
# Le poids "urls" (typosquatting, TLD suspect, IP directe...) est le signal le plus
# fiable et discriminant pour ce type d'attaque : on le monte, on baisse "ti" en
# conséquence.
WEIGHTS_FULL = {
    "headers":  0.20,
    "nlp":      0.20,
    "urls":     0.30,   # était 0.20
    "attach":   0.15,
    "ti":       0.05,   # était 0.15 — quasi toujours 0 sur du phishing "zero-day"
    "images":   0.05,
    "url_susp": 0.10,   # était 0.05 — signal fort, sous-valorisé
}
WEIGHTS_TEXT = {
    "nlp":      0.20,   # était 0.25 (0.30 à l'origine)
    "urls":     0.55,
    "ti":       0.15,
    "url_susp": 0.10,   # était 0.05
}

# Types d'attaque détectables
ATTACK_PATTERNS = {
    "credential_harvesting": {
        "keywords": ["verify","account","password","login","confirm","suspended","security"],
        "requires": ["urls"],
        "description": "Vol d'identifiants via faux formulaire de connexion",
    },
    "malware_delivery": {
        "keywords": [],
        "requires": ["attachments"],
        "description": "Livraison de logiciel malveillant via pièce jointe",
    },
    "bec": {  # Business Email Compromise
        "keywords": ["wire transfer","payment","invoice","ceo","urgent","confidential"],
        "requires": [],
        "description": "Compromission de messagerie professionnelle (BEC/fraude au virement)",
    },
    "spear_phishing": {
        "keywords": [],
        "requires": ["headers"],
        "description": "Hameçonnage ciblé — usurpation d'identité précise",
    },
    "brand_impersonation": {
        "keywords": [],
        "requires": ["urls"],
        "description": "Usurpation d'une marque connue (typosquatting détecté)",
    },
}


# ──────────────────────────────────────────────────────────────
# Dataclass résultat agent
# ──────────────────────────────────────────────────────────────

@dataclass
class AgentDecision:
    modules_run:      list  = field(default_factory=list)
    modules_skipped:  list  = field(default_factory=list)
    execution_order:  list  = field(default_factory=list)
    early_exit:       bool  = False
    early_exit_reason: str  = ""
    reanalysis_count: int   = 0
    reanalysis_log:   list  = field(default_factory=list)
    contradictions:   list  = field(default_factory=list)
    attack_pattern:   str   = "unknown"
    attack_description: str = ""
    confidence_level: str   = "medium"   # low / medium / high / very_high
    confidence_score: float = 0.0        # 0-1, convergence des modules
    trail:            list  = field(default_factory=list)   # log humain lisible
    elapsed_ms:       float = 0.0


# ──────────────────────────────────────────────────────────────
# OrchestratorAgent
# ──────────────────────────────────────────────────────────────

class OrchestratorAgent:
    """
    Agent orchestrateur du pipeline DASEC.

    Responsabilités :
      1. ROUTER      — décide quels modules s'exécutent selon le contenu de l'email
      2. SEQUENCER   — ordonne les modules (fast → slow, cheap → expensive)
      3. JUDGE       — détecte les contradictions et renvoie en re-analyse ciblée
      4. CLASSIFIER  — identifie le type d'attaque
      5. CALIBRATOR  — évalue la confiance globale (convergence inter-modules)
      6. EARLY EXIT  — court-circuite le LLM si le verdict est déjà évident
    """

    def __init__(self, parsed: dict, mode: str = "full",
                 suspect_threshold: float = DEFAULT_SUSPECT_THRESHOLD,
                 phishing_threshold: float = DEFAULT_PHISHING_THRESHOLD):
        """
        parsed : résultat de parse_eml() ou dict minimal pour mode text
        mode   : "full" (eml) | "text_only"
        suspect_threshold / phishing_threshold : seuils de verdict, à passer depuis
            api_v2.py (SCORE_THRESHOLD_SUSPECT / SCORE_THRESHOLD_PHISHING) pour que
            les deux fichiers restent synchronisés sans import circulaire.
        """
        self.parsed = parsed
        self.mode   = mode
        self.dec    = AgentDecision()
        self._t0    = time.time()

        self.suspect_threshold  = suspect_threshold
        self.phishing_threshold = phishing_threshold
        # Marges utilisées pour détecter une contradiction LLM vs score numérique.
        self.llm_override_floor = max(0.0, suspect_threshold - 0.10)
        self.llm_override_ceil  = min(1.0, phishing_threshold + 0.05)

    # ── 1. ROUTER ─────────────────────────────────────────────

    def route(self) -> dict:
        """
        Analyse le contenu disponible et retourne un dict
        { module_name: bool } indiquant si le module doit s'exécuter.
        """
        p   = self.parsed
        cfg = {}

        has_images      = bool(p.get("images"))
        has_attachments = bool(p.get("attachments"))
        has_urls        = bool(p.get("urls_in_html") or p.get("urls_in_text") or
                               p.get("urls_in_body"))   # compat mode text
        has_headers     = self.mode == "full"
        has_text        = bool((p.get("full_text") or p.get("text") or "").strip())

        # Toujours actifs si présents
        cfg["headers"]     = has_headers
        cfg["nlp"]         = has_text
        cfg["urls"]        = has_urls
        cfg["images"]      = has_images
        cfg["attachments"] = has_attachments

        # Threat Intel : seulement si on a des URLs, IPs ou hashes à checker
        ips_found = p.get("_ips_found", [])   # injecté après analyze_headers()
        hashes    = [a["sha256"] for a in p.get("attachments", [])]
        cfg["threat_intel"] = has_urls or bool(ips_found) or bool(hashes)

        # RAG : toujours utile si on a du texte
        cfg["rag"] = has_text

        # LLM : désactivé si early exit (décidé plus tard dans run())
        cfg["llm"] = True

        # Log des décisions de routing
        for mod, active in cfg.items():
            if active:
                self.dec.modules_run.append(mod)
                self._log(f"✅ Module activé     : {mod}")
            else:
                self.dec.modules_skipped.append(mod)
                self._log(f"⏭️  Module ignoré     : {mod} (contenu absent)")

        return cfg

    # ── 2. SEQUENCER ──────────────────────────────────────────

    def sequence(self, cfg: dict) -> list:
        """
        Retourne la liste ordonnée des modules à exécuter.
        Ordre : rapides et déterministes en premier, LLM en dernier.
        """
        ORDER = ["headers", "attachments", "urls", "images", "nlp", "threat_intel", "rag", "llm"]
        seq = [m for m in ORDER if cfg.get(m, False)]
        self.dec.execution_order = seq
        self._log(f"📋 Ordre d'exécution : {' → '.join(seq)}")
        return seq

    # ── 3. EARLY EXIT ─────────────────────────────────────────

    # Indicateurs "certains" — preuve quasi-directe de malveillance, indépendante
    # de toute pondération probabiliste. Le texte/NLP (DistilBERT/LR) n'apparaît
    # JAMAIS ici : c'est un signal de modèle, probabiliste par nature, il reste
    # un contributeur pondéré du score global mais ne doit jamais, seul, forcer
    # un verdict PHISHING.
    _CERTAIN_FINDING_MARKERS = (
        "URLHaus blacklist",
        "OpenPhish blacklist",
        "Hash malveillant",
        "URL malveillante (VT",
        "IP malveillante (AbuseIPDB",
        "Double extension dangereuse",
        "Macros VBA",
    )

    def check_early_exit(self,
                         header_r: dict, url_r: dict, attach_r: dict,
                         image_r: dict, text_r: dict, ti_r: dict) -> Optional[str]:
        """
        Appelé après les modules déterministes (avant LLM/RAG).
        Retourne "PHISHING" / "LEGITIME" / None.

        Le score NLP (text_r) n'intervient QUE dans la formule combinée du Cas 4
        (score brut), jamais comme déclencheur autonome — voir _CERTAIN_FINDING_MARKERS.
        """
        header_s = header_r.get("score", 0.0)
        url_s    = url_r.get("score", 0.0)
        attach_s = attach_r.get("score", 0.0)
        nlp_s    = text_r.get("score", 0.0)
        ti_s     = ti_r.get("score", 0.0)

        # Cas 1 — IOC confirmé VirusTotal/AbuseIPDB → verdict immédiat
        if ti_s >= 0.85:
            self.dec.early_exit = True
            self.dec.early_exit_reason = f"IoC externe confirmé (TI score={ti_s:.2f})"
            self._log(f"🚨 EARLY EXIT PHISHING : {self.dec.early_exit_reason}")
            return "PHISHING"

        # Cas 2 — Pièce jointe exécutable confirmée
        if attach_s >= 0.80:
            self.dec.early_exit = True
            self.dec.early_exit_reason = f"Pièce jointe malveillante (attach score={attach_s:.2f})"
            self._log(f"🚨 EARLY EXIT PHISHING : {self.dec.early_exit_reason}")
            return "PHISHING"

        # Cas 2bis — URL en liste noire confirmée (URLHaus/OpenPhish) ou score URL
        # très élevé (typosquat + TLD + autres red flags cumulés)
        if url_s >= 0.80:
            self.dec.early_exit = True
            self.dec.early_exit_reason = f"URL fortement suspecte/blacklistée (url score={url_s:.2f})"
            self._log(f"🚨 EARLY EXIT PHISHING : {self.dec.early_exit_reason}")
            return "PHISHING"

        # Cas 2ter — Scan direct des indicateurs "certains" dans les findings bruts,
        # indépendamment du score agrégé (au cas où d'autres modules bas noient le
        # signal dans la moyenne pondérée)
        all_findings_text = " | ".join(
            header_r.get("findings", []) + url_r.get("findings", []) +
            attach_r.get("findings", []) + image_r.get("findings", [])
        )
        for marker in self._CERTAIN_FINDING_MARKERS:
            if marker in all_findings_text:
                self.dec.early_exit = True
                self.dec.early_exit_reason = f"Indicateur certain détecté : '{marker}'"
                self._log(f"🚨 EARLY EXIT PHISHING : {self.dec.early_exit_reason}")
                return "PHISHING"

        # Cas 3 — Score brut global déjà très haut → skip LLM
        # (le NLP participe ICI, mais dilué avec 3 autres signaux — jamais seul)
        raw = (header_s * 0.25 + url_s * 0.30 + nlp_s * 0.25 + ti_s * 0.20)
        if raw >= EARLY_EXIT_THRESHOLD:
            self.dec.early_exit = True
            self.dec.early_exit_reason = f"Score brut élevé ({raw:.2f}) — LLM non nécessaire"
            self._log(f"⚡ EARLY EXIT PHISHING (score brut) : {raw:.2f}")
            return "PHISHING"

        # Cas 4 — Email manifestement légitime (tous les modules très bas)
        if all(s <= 0.08 for s in [header_s, url_s, nlp_s, ti_s]):
            self.dec.early_exit = True
            self.dec.early_exit_reason = "Tous les modules nominaux — email légitime"
            self._log(f"✅ EARLY EXIT LEGITIME : score global estimé très bas")
            return "LEGITIME"

        return None

    # ── 4. JUDGE ──────────────────────────────────────────────

    def judge(self,
              score_global: float,
              nlp_r: dict,
              url_r: dict,
              header_r: dict,
              ti_r: dict,
              report: dict,
              image_r: dict = None) -> dict:
        """
        Analyse la cohérence des scores inter-modules.
        Retourne un dict de contradictions avec les modules à re-analyser.
        """
        contradictions = []
        image_r = image_r or {}

        nlp_s    = nlp_r.get("score", 0.0)
        url_s    = url_r.get("score", 0.0)
        ti_s     = ti_r.get("score", 0.0)
        llm_verd = report.get("verdict", "")

        # Contradiction 1 — NLP et URLs divergent fortement
        if abs(nlp_s - url_s) > CONTRADICTION_DELTA and url_s > 0:
            dominant = "urls" if url_s > nlp_s else "nlp"
            c = {
                "type": "nlp_url_divergence",
                "detail": f"NLP={nlp_s:.2f} vs URLs={url_s:.2f} (delta={abs(nlp_s-url_s):.2f})",
                "module_to_retry": dominant,
                "reason": ("Texte propre mais URLs suspectes → possible spear phishing silencieux"
                           if url_s > nlp_s else
                           "Texte alarmant mais URLs saines → possible faux positif NLP"),
            }
            contradictions.append(c)
            self._log(f"⚠️  CONTRADICTION : {c['detail']} — re-analyse : {dominant}")

        # Contradiction 2 — LLM contredit le score numérique
        if llm_verd == "PHISHING" and score_global < self.llm_override_floor:
            c = {
                "type": "llm_overreach",
                "detail": f"LLM=PHISHING mais score={score_global:.2f} < {self.llm_override_floor:.2f}",
                "module_to_retry": "llm",
                "reason": "LLM sur-détecte — score numérique trop bas pour confirmer",
            }
            contradictions.append(c)
            self._log(f"⚠️  CONTRADICTION : {c['detail']}")

        if llm_verd == "LEGITIME" and score_global > self.llm_override_ceil:
            c = {
                "type": "llm_underreach",
                "detail": f"LLM=LEGITIME mais score={score_global:.2f} > {self.llm_override_ceil:.2f}",
                "module_to_retry": "llm",
                "reason": "LLM sous-détecte — score numérique fort contredit le verdict LLM",
            }
            contradictions.append(c)
            self._log(f"⚠️  CONTRADICTION : {c['detail']}")

        # Contradiction 3 — TI confirme phishing mais verdict final est LEGITIME
        if ti_s > 0.50 and llm_verd == "LEGITIME":
            c = {
                "type": "ti_verdict_mismatch",
                "detail": f"TI={ti_s:.2f} (IoCs détectés) mais verdict=LEGITIME",
                "module_to_retry": "llm",
                "reason": "Threat Intel externe confirme des IoCs — verdict LLM doit être réévalué",
            }
            contradictions.append(c)
            self._log(f"⚠️  CONTRADICTION : {c['detail']}")

        # Contradiction 4 — Headers SPF/DKIM/DMARC tous fails mais verdict LEGITIME
        h_spf   = header_r.get("spf_pass", True)
        h_dkim  = header_r.get("dkim_pass", True)
        h_dmarc = header_r.get("dmarc_pass", True)
        if not h_spf and not h_dkim and not h_dmarc and llm_verd == "LEGITIME":
            c = {
                "type": "auth_verdict_mismatch",
                "detail": "SPF+DKIM+DMARC tous échoués mais verdict=LEGITIME",
                "module_to_retry": "headers",
                "reason": "Triple échec d'authentification incompatible avec un email légitime",
            }
            contradictions.append(c)
            self._log(f"⚠️  CONTRADICTION : {c['detail']}")

        self.dec.contradictions = contradictions
        if not contradictions:
            self._log("✅ Aucune contradiction détectée — verdict confirmé")

        return {"contradictions": contradictions, "needs_reanalysis": bool(contradictions)}

    # ── 5. ATTACK PATTERN CLASSIFIER ──────────────────────────

    def classify_attack(self,
                        url_r: dict,
                        attach_r: dict,
                        nlp_r: dict,
                        header_r: dict,
                        full_text: str = "") -> tuple:
        """
        Identifie le type d'attaque dominant selon les modules activés.
        Retourne (pattern_key, description).
        """
        text_lower = full_text.lower()
        scores = {}

        # BEC — mots-clés financiers dans le texte
        bec_hits = [kw for kw in ATTACK_PATTERNS["bec"]["keywords"] if kw in text_lower]
        scores["bec"] = len(bec_hits) * 0.25

        # Credential harvesting — mots-clés auth + URLs suspectes
        cred_hits = [kw for kw in ATTACK_PATTERNS["credential_harvesting"]["keywords"]
                     if kw in text_lower]
        url_bonus = 0.30 if url_r.get("suspicious") else 0.0
        scores["credential_harvesting"] = len(cred_hits) * 0.15 + url_bonus

        # Malware delivery — pièce jointe dangereuse
        attach_s = attach_r.get("score", 0.0)
        scores["malware_delivery"] = attach_s * 0.90 if attach_s > 0.30 else 0.0

        # Spear phishing — header mismatch (Reply-To ≠ From, Return-Path ≠ From)
        header_findings = header_r.get("findings", [])
        spear_signals = sum(1 for f in header_findings
                            if "Reply-To" in f or "Return-Path" in f)
        scores["spear_phishing"] = spear_signals * 0.35

        # Brand impersonation — typosquatting détecté dans les URLs
        url_findings = url_r.get("findings", [])
        brand_signals = sum(1 for f in url_findings if "Typosquatting" in f or "TLD suspect" in f)
        scores["brand_impersonation"] = brand_signals * 0.40

        if not scores or max(scores.values()) < 0.15:
            pattern = "generic_phishing"
            desc    = "Phishing générique — profil d'attaque non déterminé avec certitude"
        else:
            pattern = max(scores, key=scores.get)
            desc    = ATTACK_PATTERNS.get(pattern, {}).get("description", "")

        self.dec.attack_pattern     = pattern
        self.dec.attack_description = desc
        self._log(f"🎯 Pattern d'attaque : {pattern} ({desc})")
        return pattern, desc

    # ── 6. CONFIDENCE CALIBRATOR ──────────────────────────────

    def calibrate_confidence(self,
                             score_global: float,
                             module_scores: dict,
                             contradictions: list) -> tuple:
        """
        Calcule un niveau de confiance basé sur :
        - la convergence des scores entre modules
        - le nombre de contradictions
        - le score global
        Retourne (level: str, score: float).
        """
        active_scores = [v for v in module_scores.values() if v > 0]
        if not active_scores:
            return "low", 0.1

        # Variance des scores — faible variance = modules d'accord = haute confiance
        mean  = sum(active_scores) / len(active_scores)
        variance = sum((s - mean) ** 2 for s in active_scores) / len(active_scores)
        std   = variance ** 0.5

        # Base confidence inversement proportionnelle à l'écart-type
        base_confidence = max(0.0, 1.0 - std * 2)

        # Pénalité par contradiction
        contradiction_penalty = len(contradictions) * 0.15

        # Bonus si score global très tranché (< 0.20 ou > 0.80)
        clarity_bonus = 0.15 if (score_global < 0.20 or score_global > 0.80) else 0.0

        conf_score = max(0.0, min(1.0, base_confidence - contradiction_penalty + clarity_bonus))

        if conf_score >= 0.80:   level = "very_high"
        elif conf_score >= 0.60: level = "high"
        elif conf_score >= 0.40: level = "medium"
        else:                    level = "low"

        self.dec.confidence_level = level
        self.dec.confidence_score = round(conf_score, 3)
        self._log(f"📊 Confiance calculée : {level} ({conf_score:.2f}) — std={std:.2f}, contradictions={len(contradictions)}")
        return level, round(conf_score, 3)

    # ── 7. COMPUTE SCORE (centralisé) ─────────────────────────

    def compute_score(self,
                      header_r: dict,
                      url_r: dict,
                      image_r: dict,
                      attach_r: dict,
                      text_r: dict,
                      ti_r: dict) -> float:
        """
        Calcul du score global pondéré selon le mode.
        Remplace compute_global_score() dans api_v2.py.
        """
        if self.mode == "text_only":
            score = (
                text_r.get("score", 0.0)     * WEIGHTS_TEXT["nlp"] +
                url_r.get("score", 0.0)      * WEIGHTS_TEXT["urls"] +
                ti_r.get("score", 0.0)       * WEIGHTS_TEXT["ti"] +
                (len(url_r.get("suspicious", [])) > 0) * WEIGHTS_TEXT["url_susp"]
            )
        else:
            score = (
                header_r.get("score", 0.0)   * WEIGHTS_FULL["headers"] +
                text_r.get("score", 0.0)     * WEIGHTS_FULL["nlp"] +
                url_r.get("score", 0.0)      * WEIGHTS_FULL["urls"] +
                attach_r.get("score", 0.0)   * WEIGHTS_FULL["attach"] +
                ti_r.get("score", 0.0)       * WEIGHTS_FULL["ti"] +
                image_r.get("score", 0.0)    * WEIGHTS_FULL["images"] +
                (len(url_r.get("suspicious", [])) > 0) * WEIGHTS_FULL["url_susp"]
            )

        # Bonus de convergence : plusieurs indicateurs FAIBLES mais INDÉPENDANTS qui
        # pointent tous dans la même direction (headers + urls + nlp + ...) sont un
        # signal bien plus fort que leur simple somme pondérée ne le laisse penser.
        # Sans ce bonus, un email cumulant "pas d'auth" + "typosquat" + "urgence" +
        # "mailer suspect" pouvait rester sous le seuil PHISHING malgré 4+ red flags
        # clairement convergents.
        total_findings = (
            len(header_r.get("findings", [])) +
            len(url_r.get("findings", [])) +
            len(image_r.get("findings", [])) +
            len(attach_r.get("findings", []))
        )
        if total_findings >= 6:
            score += 0.15
        elif total_findings >= 4:
            score += 0.10
        elif total_findings >= 3:
            score += 0.05

        return round(min(score, 1.0), 4)

    # ── 8. RESOLVE CONTRADICTIONS ─────────────────────────────

    def resolve_verdict(self,
                        score_global: float,
                        report: dict,
                        contradictions: list,
                        reanalysis_count: int) -> dict:
        """
        Résout les contradictions et retourne le verdict final corrigé.
        Appelé après judge() si des contradictions sont détectées.

        FIX bug#A : quand le verdict change ici, on régénère aussi explication/
        recommandation/campagne/technique — sinon on garde le texte généré pour
        l'ANCIEN verdict (ex: badge SUSPECT affiché à côté d'un texte "email
        jugé légitime, aucune action requise").
        """
        verdict = report.get("verdict", "SUSPECT")
        original_verdict = verdict
        changes = []

        for c in contradictions:
            ctype = c["type"]

            if ctype == "llm_overreach":
                # LLM dit PHISHING mais score trop bas
                new_v = "SUSPECT" if score_global >= self.suspect_threshold else "LEGITIME"
                if verdict != new_v:
                    changes.append(f"Verdict corrigé {verdict} → {new_v} (LLM sur-détection)")
                    verdict = new_v

            elif ctype == "llm_underreach":
                # LLM dit LEGITIME mais score trop haut
                new_v = "PHISHING" if score_global >= self.phishing_threshold else "SUSPECT"
                if verdict != new_v:
                    changes.append(f"Verdict corrigé {verdict} → {new_v} (LLM sous-détection)")
                    verdict = new_v

            elif ctype == "ti_verdict_mismatch":
                # TI confirme des IoCs — forcer au minimum SUSPECT
                if verdict == "LEGITIME":
                    changes.append(f"Verdict corrigé LEGITIME → SUSPECT (IoCs TI confirmés)")
                    verdict = "SUSPECT"

            elif ctype == "auth_verdict_mismatch":
                # Triple échec auth — forcer au minimum SUSPECT
                if verdict == "LEGITIME":
                    changes.append(f"Verdict corrigé LEGITIME → SUSPECT (SPF+DKIM+DMARC échoués)")
                    verdict = "SUSPECT"

            elif ctype == "nlp_url_divergence":
                # Divergence NLP/URLs — si on a des URLs suspectes, pencher vers SUSPECT minimum
                if score_global >= self.suspect_threshold + 0.10 and verdict == "LEGITIME":
                    changes.append(f"Verdict maintenu SUSPECT minimum (divergence NLP/URLs)")
                    verdict = "SUSPECT"

        if changes:
            for change in changes:
                self._log(f"🔧 RÉSOLUTION : {change}")
            self.dec.reanalysis_log.extend(changes)

        # FIX : régénérer le texte si le verdict a effectivement changé, pour ne
        # jamais laisser un texte incohérent avec le badge final affiché.
        if verdict != original_verdict:
            reasons = "; ".join(changes) if changes else "réévaluation des contradictions"
            if verdict == "LEGITIME":
                report["explication"]      = f"Verdict réévalué à LEGITIME ({reasons}). Score={score_global:.2f}."
                report["recommandation"]   = "Aucune action requise."
                report["indicateurs_cles"] = []
                report["campagne_probable"] = "Aucune"
                report["technique_attck"]   = "N/A"
            elif verdict == "SUSPECT":
                report["explication"]    = f"Verdict réévalué à SUSPECT ({reasons}). Score={score_global:.2f}."
                report["recommandation"] = "Vérification manuelle requise avant classement définitif."
            elif verdict == "PHISHING":
                report["explication"]    = f"Verdict réévalué à PHISHING ({reasons}). Score={score_global:.2f}."
                report["recommandation"] = "Bloquer et mettre en quarantaine immédiatement."

        report["verdict"] = verdict
        return report

    # ── 9. RUN (point d'entrée principal) ─────────────────────

    def run(self,
            # Fonctions d'analyse à appeler (passées depuis api_v2.py)
            fn_headers,
            fn_urls,
            fn_images,
            fn_attachments,
            fn_text,
            fn_rag,
            fn_ti,
            fn_report,
            fn_sigma,
            # Constantes vides pour les modules skippés
            EMPTY_HEADER,
            EMPTY_IMAGE,
            EMPTY_ATTACH,
            # URLs extraites
            all_urls: list = None,
            full_text: str = "",
            ) -> dict:
        """
        Point d'entrée principal de l'agent.
        Remplace le bloc séquentiel dans /analyze/eml et /analyze/text.

        Retourne le résultat complet enrichi de l'agent.
        """
        all_urls = all_urls or []

        # ── Step 1 : Routing ──────────────────────────────────
        cfg = self.route()
        seq = self.sequence(cfg)

        # ── Step 2 : Exécution ordonnée des modules ───────────
        header_r = EMPTY_HEADER.copy()
        image_r  = EMPTY_IMAGE.copy()
        attach_r = EMPTY_ATTACH.copy()
        url_r    = {"score": 0.0, "total_urls": 0, "suspicious": [], "findings": []}
        text_r   = {"bert_score": 0.0, "lr_score": 0.0, "score": 0.0, "keywords": []}
        rag_r    = {"techniques": [], "apt_groups": [], "campaigns": [], "live_iocs": []}
        ti_r     = {"score": 0.0, "iocs_detected": [], "details": {}, "apis_used": {}}

        early_verdict = None

        for module in seq:
            self._log(f"▶️  Exécution : {module}")

            if module == "headers":
                header_r = fn_headers(self.parsed)
                # Injecter les IPs trouvées pour le routing TI
                self.parsed["_ips_found"] = header_r.get("ips_found", [])

            elif module == "attachments":
                if cfg.get("attachments"):
                    attach_r = fn_attachments(self.parsed.get("attachments", []))

            elif module == "urls":
                if cfg.get("urls"):
                    url_r = fn_urls(all_urls)

            elif module == "images":
                if cfg.get("images"):
                    image_r = fn_images(self.parsed.get("images", []))

            elif module == "nlp":
                combined = full_text + " " + image_r.get("ocr_text", "")
                text_r = fn_text(combined.strip() or full_text)

            elif module == "threat_intel":
                hashes = [a["sha256"] for a in self.parsed.get("attachments", [])][:2]
                ti_r = fn_ti(
                    urls=url_r.get("suspicious", [])[:3],
                    ips=header_r.get("ips_found", [])[:3],
                    hashes=hashes,
                )

            elif module == "rag":
                rag_r = fn_rag(full_text)

            # ── Vérification Early Exit après TI ─────────────
            if module == "threat_intel":
                early_verdict = self.check_early_exit(header_r, url_r, attach_r, image_r, text_r, ti_r)
                if early_verdict:
                    # Skip LLM
                    cfg["llm"] = False
                    if "llm" in seq:
                        seq.remove("llm")
                        self.dec.modules_skipped.append("llm")
                        self._log(f"⚡ LLM skippé — early exit ({early_verdict})")
                    break

        # ── Step 3 : Calcul du score global ───────────────────
        score_global = self.compute_score(header_r, url_r, image_r, attach_r, text_r, ti_r)

        # Si un verdict a été forcé par early exit (indicateur "certain" :
        # pièce jointe dangereuse, IOC confirmé VT/AbuseIPDB, blacklist URL...),
        # le score numérique affiché doit rester cohérent avec ce verdict — sinon
        # on revoit le cas confus "score=0.38 mais badge=PHISHING".
        if early_verdict == "PHISHING":
            score_global = max(score_global, self.phishing_threshold + 0.05)
        elif early_verdict == "LEGITIME":
            score_global = min(score_global, max(0.0, self.suspect_threshold - 0.05))
        score_global = round(min(score_global, 1.0), 4)

        self._log(f"📈 Score global : {score_global:.4f}")

        # ── Step 4 : Génération du rapport (LLM ou fallback) ──
        if early_verdict:
            # Rapport structuré sans LLM
            all_findings = (
                header_r.get("findings", []) +
                url_r.get("findings", []) +
                image_r.get("findings", []) +
                attach_r.get("findings", [])
            )
            report = {
                "verdict": early_verdict,
                "confiance": "haute",
                "score_final": score_global,
                "campagne_probable": (rag_r["campaigns"][0].get("campaign", "N/A")
                                      if rag_r["campaigns"] else "N/A"),
                "technique_attck": (f"{rag_r['techniques'][0].get('tech_id','')} — "
                                    f"{rag_r['techniques'][0].get('name','N/A')}"
                                    if rag_r["techniques"] else "N/A"),
                "vecteur_attaque": "lien" if url_r.get("suspicious") else "texte seul",
                "indicateurs_cles": all_findings[:5],
                "explication": f"Early exit — {self.dec.early_exit_reason}. Score={score_global:.2f}.",
                "recommandation": ("Bloquer et mettre en quarantaine immédiatement."
                                   if early_verdict == "PHISHING" else "Email légitime."),
                "iocs": {
                    "urls_suspectes": url_r.get("suspicious", []),
                    "ips_malveillantes": header_r.get("ips_found", []),
                    "hashes": [a.get("sha256", "") for a in
                               self.parsed.get("attachments", [])][:3],
                },
                "sigma_hint": url_r["suspicious"][0] if url_r.get("suspicious") else "",
            }
        else:
            report = fn_report(
                self.parsed, header_r, url_r, image_r, attach_r,
                text_r, rag_r, ti_r, score_global
            )

        # ── Step 5 : JUDGE — détection des contradictions ─────
        judge_result = self.judge(score_global, text_r, url_r, header_r, ti_r, report, image_r)

        # ── Step 6 : Résolution des contradictions ────────────
        if judge_result["needs_reanalysis"] and self.dec.reanalysis_count < MAX_REANALYSIS_LOOPS:
            self.dec.reanalysis_count += 1
            self._log(f"🔄 Re-analyse #{self.dec.reanalysis_count} (contradictions détectées)")
            report = self.resolve_verdict(
                score_global, report,
                judge_result["contradictions"],
                self.dec.reanalysis_count
            )

        # ── Step 7 : Attack Pattern Classifier ────────────────
        pattern, desc = self.classify_attack(url_r, attach_r, text_r, header_r, full_text)

        # ── Step 8 : Confidence Calibrator ────────────────────
        module_scores = {
            "headers": header_r.get("score", 0.0),
            "urls":    url_r.get("score", 0.0),
            "nlp":     text_r.get("score", 0.0),
            "ti":      ti_r.get("score", 0.0),
            "images":  image_r.get("score", 0.0),
            "attach":  attach_r.get("score", 0.0),
        }
        conf_level, conf_score = self.calibrate_confidence(
            score_global, module_scores, judge_result["contradictions"]
        )

        # ── Step 9 : Sigma rules ──────────────────────────────
        sigma_r = fn_sigma(
            report, score_global,
            {"from": self.parsed.get("from", ""),
             "subject": self.parsed.get("subject", "")}
        )

        # ── Step 10 : Finalisation ────────────────────────────
        self.dec.elapsed_ms = round((time.time() - self._t0) * 1000, 1)
        self._log(f"✅ Pipeline terminé en {self.dec.elapsed_ms}ms")

        # Enrichissement du rapport avec les métadonnées agent
        report["confiance"] = conf_level
        report["vecteur_attaque"] = report.get("vecteur_attaque", "")

        return {
            # Résultats principaux
            "score_global": score_global,
            "verdict":      report.get("verdict", "SUSPECT"),
            # Modules
            "modules": {
                "headers":      header_r,
                "urls":         url_r,
                "images":       image_r,
                "attachments":  attach_r,
                "nlp":          text_r,
                "rag":          rag_r,
                "threat_intel": ti_r,
            },
            "report":      report,
            "sigma_rules": sigma_r,
            # Métadonnées agent
            "agent": {
                "modules_run":       self.dec.modules_run,
                "modules_skipped":   self.dec.modules_skipped,
                "execution_order":   self.dec.execution_order,
                "early_exit":        self.dec.early_exit,
                "early_exit_reason": self.dec.early_exit_reason,
                "reanalysis_count":  self.dec.reanalysis_count,
                "reanalysis_log":    self.dec.reanalysis_log,
                "contradictions":    self.dec.contradictions,
                "attack_pattern":    self.dec.attack_pattern,
                "attack_description": self.dec.attack_description,
                "confidence_level":  self.dec.confidence_level,
                "confidence_score":  self.dec.confidence_score,
                "trail":             self.dec.trail,
                "elapsed_ms":        self.dec.elapsed_ms,
            },
        }

    # ── Helper ────────────────────────────────────────────────

    def _log(self, msg: str):
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3]
        entry = f"[{ts}] {msg}"
        self.dec.trail.append(entry)
        print(f"[DASEC Agent] {entry}")