# Figuras para el artículo

Las 16 figuras candidatas para el artículo, en inglés (`en/`) y en español (`es/`), en PNG a 300 ppp. La selección final se hace al escribir el artículo.

Cada figura es una versión de una figura original de `artifacts/figures/` (exploración, notebook 01) o de `artifacts/model_search/` (búsqueda y entrenamiento final, notebooks 05 y 06): el mismo código, los mismos datos, el mismo tamaño de figura y la misma paleta. Cambian el idioma de los textos, el formato de los números, los nombres de los modelos, el título general (que se quita) y la resolución. Las figuras originales no se modifican.

## Cómo se generan

Las genera `notebooks/07_paper_figures.ipynb`, que dibuja cada figura con una función que recibe el idioma y la guarda en las dos carpetas. Para regenerarlas, se ejecuta ese notebook completo; tardó unos 25 segundos en el equipo donde se entrenaron los modelos, y no entrena ni evalúa nada.

- **Exploración:** se recalculan desde `data/raw/` (leído con `load_train` y `load_test`) con el mismo código del notebook 01. Necesitan los CSV del dataset (ver `data/README.md`).
- **Modelos:** se dibujan desde los archivos de `artifacts/model_search/`, sin recalcular nada.
- **`test_pr_curves`:** es la única que necesita predicciones: los 4 modelos registrados predicen la prueba con `predict_flows`, como en la sección 8 del notebook 06. Comprueba que la PR-AUC de cada curva coincida con la guardada en `test_results.csv` con una tolerancia de 1e-6 (por el ruido de Random Forest; ver `artifacts/model_search/README.md`). La leyenda usa la PR-AUC guardada.

## Formato

| | Inglés (`en/`) | Español (`es/`) |
|---|---|---|
| Decimales y miles | punto decimal, coma de miles: `0.988`, `82,332` | coma decimal, punto de miles: `0,988`, `82.332` |
| Porcentajes | sin espacio: `16.5%` | con espacio: `16,5 %` |
| Modelos registrados | HistGradientBoosting, Random forest, MLP, Logistic regression (baseline) | HistGradientBoosting, Random forest, MLP, Regresión logística (modelo base) |
| Otras familias | Extra trees, Decision tree, Gaussian naive Bayes, Dummy | Extra trees, Árbol de decisión, Gaussian naive Bayes, Clasificador trivial |

Los ejes, las leyendas y los títulos de panel usan siempre esos nombres, nunca los nombres internos del código (`hist_gradient_boosting`, `random_forest`...). Los tipos de ataque y las variables (`sttl`, `proto`...) quedan igual en los dos idiomas.

**Sin título general.** En IEEE el título de una figura va en su leyenda (caption) en el artículo, así que las imágenes no llevan título superior; los subtítulos de cada panel sí se quedan. Lo que decía el título y no está en otra parte de la imagen debe ir en el caption:

- `test_confusion_hgb`, `false_alarms_by_category` y `numeric_differences_normals` son solo de **HistGradientBoosting**; la imagen no lo dice.
- `global_importance` usa **5.000 flujos de prueba** (la primera muestra de `global_importance.csv`).
- `test_pr_curves` muestra los **4 modelos registrados en la app**, en prueba.
- Las figuras de la exploración son del **conjunto de entrenamiento** (salvo las que comparan entrenamiento y prueba, que lo dicen en su leyenda).

Diferencias de formato con las originales, que siguen la regla de arriba:

- En las originales de la exploración, las cifras sobre las barras usaban coma de miles también en español (`119,341`); la versión en español usa punto (`119.341`), y los ejes de conteos llevan separador de miles.
- Ninguna lleva título general; las originales sí.
- Los modelos usan los nombres del artículo (tabla de arriba); las originales usaban los nombres internos en los ejes (`hist_gradient_boosting`, `logistic_regression`...), `Random Forest` y, en las curvas precisión-recall, `Red neuronal (MLP)`. En la importancia global, el panel de la regresión logística dice `Regresión logística (modelo base)`; en la original, `Regresión logística`.
- En `train_validation_gap`, cada caso es el nombre del modelo con el caso entre paréntesis (`Random forest (chosen)`, `Decision tree (default values)`, `Extra trees (no depth limit)`; en español, `(elegido)`, `(valores por defecto)`, `(sin límite de profundidad)`); el modelo base va sin paréntesis.
- En `ttl_test`, la leyenda dice `with TTL (M1/M2)` / `con TTL (M1/M2)`; en la original, `con TTL (versión de la app)`.
- Las figuras de la exploración se guardan con el borde ajustado al contenido, como las originales; al quitar el título, su alto en píxeles es un poco menor. Las de los modelos conservan el tamaño en píxeles de su figura.

## Las figuras

| Archivo | Original | Qué muestra |
|---|---|---|
| `target_distribution.png` | `artifacts/figures/` | Desbalance de clases en el entrenamiento: `label` y `attack_cat` (escala log) |
| `train_test_class_distribution.png` | `artifacts/figures/` | Proporción de cada `attack_cat` en entrenamiento y prueba |
| `repeated_flows_by_class.png` | `artifacts/figures/` | Flujos de entrenamiento que repiten un patrón ya visto, por clase |
| `ttl_by_class.png` | `artifacts/figures/` | Flujos por valor de `sttl`, `dttl` y `ct_state_ttl` y clase (el atajo de TTL) |
| `ttl_attack_rate_train_test.png` | `artifacts/figures/` | Proporción de ataques por valor de `sttl`, en entrenamiento y prueba |
| `train_test_shift.png` | `artifacts/figures/` | Distancia de Kolmogorov–Smirnov entre entrenamiento y prueba, solo normales y solo ataques |
| `defaults_scores.png` | `artifacts/model_search/` | Barrido con valores por defecto: PR-AUC y F1 macro de cada familia y método, en validación |
| `train_validation_gap.png` | `artifacts/model_search/` | Brecha entre validación y entrenamiento de los modelos registrados y de casos que sobreentrenan |
| `validation_vs_test.png` | `artifacts/model_search/` | Recall, falsas alarmas y F1 macro de las 8 familias, en validación y en prueba |
| `ttl_test.png` | `artifacts/model_search/` | El experimento de TTL en prueba: los 3 modelos elegidos con y sin TTL (M3) |
| `test_f1_per_type.png` | `artifacts/model_search/` | F1 de cada tipo de ataque en prueba, para las 8 familias |
| `test_confusion_hgb.png` | `artifacts/model_search/` | Matrices de confusión 2×2 y 9×9 de HistGradientBoosting en prueba |
| `test_pr_curves.png` | `artifacts/model_search/` | Curvas precisión-recall en prueba de los 4 modelos registrados, con su punto de operación |
| `global_importance.png` | `artifacts/model_search/` | Importancia global de las variables del detector (SHAP o contribución lineal) |
| `false_alarms_by_category.png` | `artifacts/model_search/` | Tasa de falsas alarmas de HistGradientBoosting por categoría de `proto`, `service` y `state` |
| `numeric_differences_normals.png` | `artifacts/model_search/` | Distancia de Kolmogorov–Smirnov de las variables numéricas de los normales que dan falsa alarma |

El detalle de cada figura de los modelos (cómo se calculan sus datos y sus límites) está en `artifacts/model_search/README.md`, y el de las de la exploración, en el notebook 01.
