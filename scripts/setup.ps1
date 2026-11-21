[CmdletBinding()]
param([string]$Python = 'python')
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
if ((Get-Location).Path -ne $projectRoot) { throw 'Запустите setup из корня клона.' }
& $Python -c 'import sys; assert (3,12) <= sys.version_info[:2] < (3,15), "Нужен Python 3.12–3.14"'
if ($LASTEXITCODE) { throw 'Установите Python 3.12–3.14 с python.org и повторите setup.' }
$settings = Get-Content ./config/lab.json -Raw | ConvertFrom-Json
$expectedPoetry = $settings.tools.poetry
if (-not (Get-Command poetry -ErrorAction SilentlyContinue)) {
    & $Python -m pip install --user "poetry==$expectedPoetry"
    if ($LASTEXITCODE) { throw 'Не удалось установить Poetry. Добавьте каталог Scripts в PATH.' }
}
if ((& poetry --version) -ne "Poetry (version $expectedPoetry)") {
    throw "Нужен Poetry $expectedPoetry. Установите: $Python -m pip install --user poetry==$expectedPoetry"
}
$env:POETRY_VIRTUALENVS_IN_PROJECT = 'true'
$env:POETRY_KEYRING_ENABLED = 'false'
$env:POETRY_CACHE_DIR = Join-Path $projectRoot '.tools/poetry-cache'
$env:YC_TRACE_LOG_PATH = 'NUL'
$env:YC_DISABLE_UPDATE = '1'
& poetry env use (& $Python -c 'import sys; print(sys.executable)')
if ($LASTEXITCODE) { throw 'Ошибка выбора Python.' }
& poetry sync --no-interaction
if ($LASTEXITCODE) { throw 'Ошибка установки зависимостей из poetry.lock.' }
& poetry run python scripts/bootstrap.py
if ($LASTEXITCODE) { throw 'Ошибка подготовки Terraform.' }
& poetry run python -c "import sys; from pathlib import Path; sys.path.insert(0,'scripts'); from common import private_dir; private_dir(Path('.local')); private_dir(Path('.local/yc'))"
if ($LASTEXITCODE) { throw 'Не удалось ограничить доступ к каталогу профиля YC.' }
$providerCache = Join-Path $projectRoot '.tools/provider-cache'
[void](New-Item -ItemType Directory -Path $providerCache -Force)
$env:TF_PLUGIN_CACHE_DIR = $providerCache
foreach ($module in @('yc', 'proxmox')) {
    & ./.tools/terraform.exe "-chdir=terraform/$module" init -backend=false -input=false -lockfile=readonly
    if ($LASTEXITCODE) { throw "Ошибка подготовки Terraform $module." }
}
Write-Host 'Подготовка завершена. Вход через профиль: ./.tools/bin/yc.exe --config .local/yc/config.yaml init'
Write-Host 'Для команд управления с этим профилем добавляйте --yc-profile. Ввод окружения: . ./scripts/env.ps1'
