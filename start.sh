#!/bin/bash
set -e

MODEL_DIR=/app/models
BERT_DIR=$MODEL_DIR/distilbert-5000/final
TFIDF_PATH=$MODEL_DIR/tfidf_lr_pipeline.pkl

mkdir -p $BERT_DIR
mkdir -p /app/data/vectorstore
mkdir -p /app/data/ioc_cache
mkdir -p /tmp/dasec_reports

# Installe gdown si absent
pip install gdown -q

# Télécharge tfidf_lr_pipeline.pkl si absent
if [ ! -f "$TFIDF_PATH" ]; then
    echo "⏳ Téléchargement tfidf_lr_pipeline.pkl..."
    gdown "12JEG6D6y3lfyYkrXdfs6tOed8chPjALt" -O $TFIDF_PATH
    echo "✅ tfidf_lr_pipeline.pkl téléchargé"
fi

# Télécharge le dossier BERT si absent
if [ ! -f "$BERT_DIR/config.json" ]; then
    echo "⏳ Téléchargement modèle BERT..."
    gdown --folder "1oziQDzwGxmnvXknRiFsHonC7ydnjFNXo" -O $MODEL_DIR/distilbert-5000 --remaining-ok
    echo "✅ Modèle BERT téléchargé"
fi

echo "✅ Tous les modèles sont prêts"
uvicorn api_v2:app --host 0.0.0.0 --port 8000