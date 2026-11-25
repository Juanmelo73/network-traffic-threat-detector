# Resultados de la búsqueda de modelos

Resultados de `notebooks/05_models.ipynb` y de `src/threat_detector/ml/training.py`, para el artículo y la presentación. Todos los valores salen de la parte de entrenamiento y de la parte de validación del archivo oficial de entrenamiento de UNSW-NB15. La partición de prueba no se usa en ninguno de estos archivos.

## Tablas

| Archivo | Qué contiene |
|---|---|
| `search_results.csv` | Una fila por combinación entrenada y medida en validación: el barrido con valores por defecto (`phase` = 1), la búsqueda de hiperparámetros (`phase` = 2) y las curvas de validación (`phase` = `curve`). Trae la familia, la tarea (`detector` o `attack_type`), el método de preprocesamiento, los hiperparámetros (`params`), los valores fijos que no son los de scikit-learn (`fixed_params`), las métricas de validación y de entrenamiento, el tamaño y los tiempos. La escribe `run_search`, una fila apenas termina cada combinación. |
| `unavoidable_type_errors.csv` | Por tipo de ataque, en la parte de entrenamiento: cuántos ataques están en grupos de flujos idénticos con otros tipos, cuántos se equivocan aunque el modelo memorice (`certain_errors`) y cuántos empatan con otro tipo (`tied_flows`). La fila `Total` trae el mínimo exacto de errores (`min_errors`). |
| `label_mixed_groups.csv` | Grupos de flujos idénticos que mezclan flujos normales y ataques en la parte de entrenamiento: cuántos son, cuántos flujos tienen y los errores mínimos del detector. |
| `train_validation_gap.csv` | Brecha entre entrenamiento y validación (PR-AUC y tasa de falsas alarmas del detector, F1 macro del clasificador) de los 4 modelos que se registran en la app y de casos de la búsqueda que sobreentrenan. |

## Figuras

| Archivo | Qué muestra |
|---|---|
| `defaults_scores.png` | PR-AUC del detector y F1 macro del clasificador de cada familia con sus valores por defecto, por método de preprocesamiento. |
| `ttl_m2_vs_m3.png` | Tasa de falsas alarmas de cada familia con M2 (con las variables de TTL) y con M3 (sin ellas). |
| `curves_random_forest.png`, `curves_extra_trees.png`, `curves_hist_gradient_boosting.png` | Curvas de validación: la métrica de entrenamiento y la de validación al variar un hiperparámetro desde la combinación elegida. |
| `train_validation_gap.png` | La brecha de `train_validation_gap.csv`, en PR-AUC y en F1 macro. |
