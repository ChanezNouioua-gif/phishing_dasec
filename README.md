# DASEC — Déploiement Docker

## Prérequis
- Docker + Docker Compose installés
- Les dossiers models/ et data/ téléchargés depuis Google Drive

## Structure attendue
dasec/
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── api_v2.py
├── .env
├── models/
│   ├── distilbert-5000/final/
│   └── tfidf_lr_pipeline.pkl
└── data/
    ├── vectorstore/
    ├── ioc_cache/
    └── dasec.db

## Lancement
# 1. Créer le .env depuis l'exemple
cp .env.example .env
# Remplir les clés dans .env

# 2. Builder l'image
docker-compose build

# 3. Lancer
docker-compose up -d

# 4. Vérifier
curl http://localhost:8000/health

# 5. Tester
curl -X POST http://localhost:8000/analyze/text -H "Content-Type: application/json" -d '{"text": "URGENT verify your account http://secure-login.tk/verify", "subject": "Alert", "sender": "security@paypa1.com"}'

## Endpoints
- GET  /health
- POST /analyze/text
- POST /analyze/eml
- GET  /history
- GET  /stats
- GET  /report/pdf/{analysis_id}
