# Datos

El proyecto usa el dataset **UNSW-NB15**, con su partición oficial de entrenamiento y prueba.

## Por qué los datos no están en el repositorio

Los CSV **no se suben a git**. Las carpetas `data/raw/` y `data/processed/` están en el `.gitignore` por estas razones:

- **Tamaño:** los archivos pesan cerca de 47 MB en total. Git no está hecho para guardar archivos grandes, y cada versión quedaría para siempre en el historial.
- **Licencia:** el dataset es de sus autores y se distribuye para uso académico desde su fuente oficial. La licencia MIT del repositorio cubre el código, no los datos.
- **Fuente única:** si cada integrante descarga los archivos de la fuente oficial, todos trabajamos con la misma versión.

## Cómo obtener los archivos

1. Entrar a la página oficial: https://research.unsw.edu.au/projects/unsw-nb15-dataset
2. Descargar los tres archivos de la partición oficial de entrenamiento y prueba ("Training and Testing Sets") y la descripción de variables.
3. Copiarlos en `data/raw/` **sin cambiarles el nombre**:

```
data/raw/
├── UNSW_NB15_training-set.csv
├── UNSW_NB15_testing-set.csv
└── NUSW-NB15_features.csv
```

> **Nota sobre el nombre:** el archivo de variables se llama `NUSW-NB15_features.csv`, con "NUSW" en lugar de "UNSW". Así lo publica la fuente oficial. Se deja con ese nombre para que nadie tenga que renombrarlo.

Desde WSL, una forma sencilla de copiarlos es abrir la carpeta en el Explorador de Windows con `explorer.exe data/raw` y arrastrar los archivos ahí.

## Contenido de cada archivo

| Archivo | Filas (flujos) | Columnas | Normal (`label = 0`) | Ataque (`label = 1`) |
|---|---|---|---|---|
| `UNSW_NB15_training-set.csv` | 175.341 | 45 | 56.000 | 119.341 |
| `UNSW_NB15_testing-set.csv` | 82.332 | 45 | 37.000 | 45.332 |
| `NUSW-NB15_features.csv` | 49 variables | 4 (`No.`, `Name`, `Type `, `Description`) | — | — |

Si al cargar los archivos los números no coinciden con esta tabla, la descarga quedó incompleta o se trata de otra versión del dataset.

### Etiquetas

- `label`: 0 si el flujo es normal y 1 si es un ataque.
- `attack_cat`: `Normal` o uno de los 9 tipos de ataque. Las clases están muy desbalanceadas (por ejemplo, `Worms` tiene solo 130 registros en entrenamiento).
- `id` es solo un número de fila y **nunca** se usa como variable. Cuando la tarea es binaria, `attack_cat` tampoco se usa como variable.

### Diferencias entre la descripción y las particiones

`NUSW-NB15_features.csv` describe las **49 variables del dataset completo**, pero las particiones tienen **45 columnas**:

- No traen `srcip`, `sport`, `dstip`, `dsport`, `stime` ni `ltime`.
- Agregan `id` (número de fila) y `rate`, que no aparece en la descripción.
- Algunas variables tienen otro nombre en las particiones:

| En la descripción | En las particiones |
|---|---|
| `smeansz` | `smean` |
| `dmeansz` | `dmean` |
| `sintpkt` | `sinpkt` |
| `dintpkt` | `dinpkt` |
| `res_bdy_len` | `response_body_len` |
| `ct_src_ ltm` (con espacio) | `ct_src_ltm` |

Además, los nombres de la descripción mezclan mayúsculas y minúsculas (por ejemplo, `Spkts`) y la columna de tipo se llama `Type `, con un espacio al final. Para cruzarla con las particiones conviene pasar los nombres a minúsculas y quitarles los espacios.

## Cómo leer los archivos

Los dos CSV de datos se leen con la codificación por defecto (UTF-8):

```python
import pandas as pd

train = pd.read_csv("data/raw/UNSW_NB15_training-set.csv")
test = pd.read_csv("data/raw/UNSW_NB15_testing-set.csv")
```

El archivo de variables **fue creado en Windows** y necesita `encoding="cp1252"`:

```python
features = pd.read_csv("data/raw/NUSW-NB15_features.csv", encoding="cp1252")
```

Con UTF-8 la lectura falla, porque el archivo usa el byte `0x92` para el apóstrofo `’`, y ese byte no es válido en UTF-8. Con `latin-1` no hay error, pero ese byte se lee como un carácter invisible. `cp1252` (Windows-1252) es la codificación que lo interpreta correctamente.

## Uso de la partición de prueba

`UNSW_NB15_testing-set.csv` se usa para **evaluar una sola vez, al final**. El umbral y los demás ajustes se hacen con una validación separada a partir del conjunto de entrenamiento.

Durante la exploración, la prueba solo se abre para verificar que es compatible con el entrenamiento (mismas columnas, tipos y categorías) y para comparar distribuciones. **Ninguna decisión de preparación ni ningún valor aprendido (categorías conocidas, escalas, etc.) sale de la prueba**: todo se calcula con el entrenamiento.

## `data/processed/`

Aquí van los datos derivados (por ejemplo, ya preprocesados) que genere el código del proyecto. Tampoco se suben a git, porque se pueden regenerar a partir de `data/raw/`.

## Cita

El dataset es de uso académico. Cualquier trabajo que lo use, incluido el artículo de este proyecto, debe citar a sus autores:

- Moustafa, N., & Slay, J. (2015). UNSW-NB15: a comprehensive data set for network intrusion detection systems (UNSW-NB15 network data set). En *2015 Military Communications and Information Systems Conference (MilCIS)* (pp. 1–6). IEEE.
- Moustafa, N., & Slay, J. (2016). The evaluation of Network Anomaly Detection Systems: Statistical analysis of the UNSW-NB15 data set and the comparison with the KDD99 data set. *Information Security Journal: A Global Perspective*, 25(1–3), 18–31.
