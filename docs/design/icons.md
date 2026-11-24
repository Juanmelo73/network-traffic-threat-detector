# Íconos

Íconos de **Lucide v1.77.0** (paquete `lucide-static`), copiados en `assets/icons.svg` como
`<symbol id="icon-NOMBRE">`. Licencia ISC de Lucide y, para los íconos que vienen de Feather, MIT de
Cole Bemis: texto completo en `assets/LICENSE-lucide.txt` y dentro de `icons.svg`.

## Cómo se usan

```html
<svg class="icon" aria-hidden="true" focusable="false"><use href="assets/icons.svg#icon-play"/></svg>
```

En JavaScript, `icon('play')` de `common.js`. El ícono toma el color del texto. Los íconos son
decorativos (`aria-hidden="true"`): el significado lo da el texto que los acompaña; un botón de solo
ícono lleva `aria-label` en español. Abrir `icons.svg` directamente muestra un lienzo vacío: los
símbolos solo se dibujan cuando una página los usa.

## Los 26 íconos

| Ícono | Significado |
|---|---|
| list | Consola; "Abrir en la consola" y "Abrir en la cola de alertas" |
| activity | Simulación; "Simular este análisis"; etiqueta "Reproducción del análisis" |
| cpu | Modelos |
| sun / moon | Cambiar a modo claro / oscuro |
| upload | Zona de carga del archivo |
| file-text | Botones de la muestra |
| link | Copiar enlace |
| x | Cerrar el panel; resultado incorrecto |
| play / pause | Iniciar o reanudar / pausar la simulación |
| rotate-ccw | Reiniciar y "Reproducir de nuevo" |
| octagon-alert, triangle-alert, circle-alert, circle-minus, circle-check | Severidad crítica, alta, media, baja y normal |
| circle-check | También: "En uso", "Análisis listo" y estados vacíos |
| circle-x | Error |
| info | Recuadro informativo y nota de la muestra |
| check | Resultado correcto; característica presente |
| arrow-left / arrow-right | Leyenda de la explicación (hacia «normal» / hacia «ataque») |
| chevron-left / chevron-right | Página anterior / siguiente |
| star | Mejor valor en la comparación |
| flask-conical | Modelo simulado |

## Agregar un ícono

1. Tomar el SVG del mismo paquete y versión (`lucide-static@1.77.0`).
2. Copiar su contenido como un nuevo `<symbol id="icon-NOMBRE" viewBox="0 0 24 24">` en `icons.svg`.
3. Agregarlo a esta tabla. La prueba `test_every_icon_used_exists` falla si una página usa un ícono
   que no está en `icons.svg`; la que hoy exige 26 se actualiza al nuevo total.
