#!/bin/bash

# Script para subir cambios a GitHub y reemplazar el contenido existente
# Uso: ./push_to_github.sh

set -e

echo "🚀 Preparando para subir cambios a GitHub..."
echo ""

# Verificar que estamos en el directorio correcto
if [ ! -f "neluxmatizer.py" ]; then
    echo "❌ Error: No se encontró neluxmatizer.py"
    echo "   Asegúrate de ejecutar este script desde el directorio del proyecto"
    exit 1
fi

# Verificar que git está inicializado
if [ ! -d ".git" ]; then
    echo "❌ Error: No se encontró un repositorio Git"
    echo "   Ejecuta primero: git init"
    exit 1
fi

# Mostrar estado actual
echo "📊 Estado actual del repositorio:"
git status --short
echo ""

# Preguntar confirmación
read -p "¿Deseas continuar y subir todos los cambios? (s/n): " confirm
if [ "$confirm" != "s" ] && [ "$confirm" != "S" ]; then
    echo "❌ Operación cancelada"
    exit 0
fi

# Agregar todos los archivos
echo ""
echo "📦 Agregando archivos al staging..."
git add -A

# Mostrar qué se va a commitear
echo ""
echo "📝 Archivos que se van a commitear:"
git status --short
echo ""

# Hacer commit
echo "💾 Creando commit..."
read -p "Mensaje del commit (Enter para usar mensaje por defecto): " commit_msg
if [ -z "$commit_msg" ]; then
    commit_msg="Update: Mejoras en instalación, documentación y limpieza del proyecto"
fi

git commit -m "$commit_msg"

# Mostrar información del remote
echo ""
echo "🔗 Remote configurado:"
git remote -v
echo ""

# Preguntar si hacer force push
echo "⚠️  ADVERTENCIA: Esto reemplazará el contenido en GitHub"
read -p "¿Hacer force push? (s/n): " force_confirm

if [ "$force_confirm" == "s" ] || [ "$force_confirm" == "S" ]; then
    echo ""
    echo "🚀 Haciendo force push a GitHub..."
    git push -f origin master
    echo ""
    echo "✅ ¡Cambios subidos exitosamente a GitHub!"
else
    echo ""
    echo "📤 Haciendo push normal a GitHub..."
    git push origin master
    echo ""
    echo "✅ ¡Cambios subidos exitosamente a GitHub!"
fi

echo ""
echo "🎉 ¡Listo! Puedes ver los cambios en:"
git remote get-url origin
echo ""

