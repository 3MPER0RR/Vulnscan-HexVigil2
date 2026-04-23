#!/usr/bin/env bash
# =============================================================================
# VulnScan — Interactive Menu
# =============================================================================

# ── Colori ────────────────────────────────────────────────────────────────────
RED='\033[91m'
ORANGE='\033[38;5;214m'
YELLOW='\033[93m'
CYAN='\033[96m'
GREEN='\033[92m'
MAGENTA='\033[95m'
WHITE='\033[97m'
GRAY='\033[90m'
BOLD='\033[1m'
RESET='\033[0m'

# ── Configurazione ─────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="python3"
MAIN="$SCRIPT_DIR/main.py"
NVD_SCRIPT="$SCRIPT_DIR/nvd_lookup.py"
AI_SCRIPT="$SCRIPT_DIR/ai_analysis.py"
RESULTS_DIR="$SCRIPT_DIR/results"
mkdir -p "$RESULTS_DIR"

# ── Banner ─────────────────────────────────────────────────────────────────────
print_banner() {
    clear
    echo -e "${MAGENTA}${BOLD}"
    echo "         ⧗▸◂▸◂▸◂▸◂▸◂▸◂▸◂▸◂▸◂▸◂▸◂▸◂⧗"
    echo "         ⧗◌◌◌◌◌◌◌◌◌◌◌◌◌◌◌◌◌◌◌◌◌◌◌◌⧗"
    echo "         ⧗◌◌◌◌◌◌◌◌HexVigil◌◌◌◌◌◌◌◌⧗"
    echo "         ⧗◌◌◌◌◌◌◌◌◌◌◌◌◌◌◌◌◌◌◌◌◌◌◌◌⧗"
    echo "         ⧗▸◂▸◂▸◂▸◂▸◂▸◂▸◂▸◂▸◂▸◂▸◂▸◂⧗"
    echo -e "${RESET}${GRAY}  Static Vulnerability Scanner — Interactive Menu${RESET}"
    echo -e "${GRAY}  ══════════════════════════════════════════════${RESET}"
    echo ""
}

# ── Menu principale ────────────────────────────────────────────────────────────
print_menu() {
    echo -e "  ${WHITE}${BOLD}Seleziona un'operazione:${RESET}"
    echo ""
    echo -e "  ${CYAN}${BOLD}[1]${RESET}  Scan statico            ${GRAY}— Analisi normale o filtrata per severità${RESET}"
    echo -e "  ${YELLOW}${BOLD}[2]${RESET}  Scan + CVE/CWE lookup   ${GRAY}— Arricchisce i findings con dati NVD${RESET}"
    echo -e "  ${MAGENTA}${BOLD}[3]${RESET}  Scan completo + AI      ${GRAY}— Analisi statica, CVE/CWE e analisi AI${RESET}"
    echo -e "  ${GRAY}${BOLD}[0]${RESET}  Esci"
    echo ""
}

# ── Input: percorso target ─────────────────────────────────────────────────────
ask_target() {
    echo -e "  ${WHITE}Percorso file o directory da scansionare:${RESET}"
    echo -ne "  ${CYAN}▶ ${RESET}"
    read -r TARGET
    if [[ ! -e "$TARGET" ]]; then
        echo -e "\n  ${RED}Errore: percorso non trovato → $TARGET${RESET}\n"
        return 1
    fi
    return 0
}

# ── Input: severità minima ─────────────────────────────────────────────────────
ask_severity() {
    echo ""
    echo -e "  ${WHITE}Severità minima da mostrare:${RESET}"
    echo -e "  ${GRAY}[1] CRITICAL  [2] HIGH  [3] MEDIUM  [4] LOW  [5] Tutte${RESET}"
    echo -ne "  ${CYAN}▶ ${RESET}"
    read -r SEV_CHOICE
    case "$SEV_CHOICE" in
        1) SEVERITY="CRITICAL" ;;
        2) SEVERITY="HIGH" ;;
        3) SEVERITY="MEDIUM" ;;
        4) SEVERITY="LOW" ;;
        *) SEVERITY="" ;;
    esac
}

# ── Timestamp per i file di output ─────────────────────────────────────────────
timestamp() {
    date +"%Y%m%d_%H%M%S"
}

# =============================================================================
# OPZIONE 1 — Scan statico
# =============================================================================
run_scan_static() {
    print_banner
    echo -e "  ${CYAN}${BOLD}── SCAN STATICO ─────────────────────────────────${RESET}\n"

    ask_target || return
    ask_severity

    TS=$(timestamp)
    OUTPUT_FILE="$RESULTS_DIR/scan_${TS}.txt"

    echo ""
    echo -e "  ${GRAY}Avvio scansione...${RESET}\n"

    CMD="$PYTHON $MAIN \"$TARGET\" -v"
    [[ -n "$SEVERITY" ]] && CMD="$CMD --severity $SEVERITY"

    eval "$CMD" | tee "$OUTPUT_FILE"

    echo -e "\n  ${GREEN}${BOLD}Report salvato in:${RESET} ${WHITE}$OUTPUT_FILE${RESET}\n"
    press_enter
}

# =============================================================================
# OPZIONE 2 — Scan + CVE/CWE lookup via NVD
# =============================================================================
run_scan_nvd() {
    print_banner
    echo -e "  ${YELLOW}${BOLD}── SCAN + CVE/CWE LOOKUP ────────────────────────${RESET}\n"

    ask_target || return
    ask_severity

    TS=$(timestamp)
    SCAN_FILE="$RESULTS_DIR/scan_${TS}.json"
    NVD_FILE="$RESULTS_DIR/nvd_${TS}.txt"

    echo ""
    echo -e "  ${GRAY}Step 1/2 — Scansione statica...${RESET}"

    CMD="$PYTHON $MAIN \"$TARGET\" -v"
    [[ -n "$SEVERITY" ]] && CMD="$CMD --severity $SEVERITY"
    eval "$CMD" | tee "$RESULTS_DIR/scan_raw_${TS}.txt"

    echo ""
    echo -e "  ${GRAY}Step 2/2 — CVE/CWE lookup su NVD...${RESET}\n"

    $PYTHON "$NVD_SCRIPT" --target "$TARGET" --severity "$SEVERITY" \
        | tee "$NVD_FILE"

    echo -e "\n  ${GREEN}${BOLD}Report NVD salvato in:${RESET} ${WHITE}$NVD_FILE${RESET}\n"
    press_enter
}

# =============================================================================
# OPZIONE 3 — Scan completo + AI
# =============================================================================
run_scan_full_ai() {
    print_banner
    echo -e "  ${MAGENTA}${BOLD}── SCAN COMPLETO + AI ───────────────────────────${RESET}\n"

    ask_target || return
    ask_severity

    TS=$(timestamp)
    RAW_FILE="$RESULTS_DIR/raw_${TS}.txt"
    NVD_FILE="$RESULTS_DIR/nvd_${TS}.txt"
    AI_FILE="$RESULTS_DIR/ai_report_${TS}.txt"

    echo ""
    echo -e "  ${GRAY}Step 1/3 — Scansione statica...${RESET}\n"
    CMD="$PYTHON $MAIN \"$TARGET\" -v"
    [[ -n "$SEVERITY" ]] && CMD="$CMD --severity $SEVERITY"
    eval "$CMD" | tee "$RAW_FILE"

    echo ""
    echo -e "  ${GRAY}Step 2/3 — CVE/CWE lookup su NVD...${RESET}\n"
    $PYTHON "$NVD_SCRIPT" --target "$TARGET" --severity "$SEVERITY" \
        | tee "$NVD_FILE"

    echo ""
    echo -e "  ${GRAY}Step 3/3 — Analisi AI in corso...${RESET}\n"
    $PYTHON "$AI_SCRIPT" \
        --scan-report "$RAW_FILE" \
        --nvd-report  "$NVD_FILE" \
        | tee "$AI_FILE"

    echo ""
    echo -e "  ${GREEN}${BOLD}Report completo salvato in:${RESET} ${WHITE}$AI_FILE${RESET}"
    echo -e "  ${GRAY}Tutti i file di questa sessione sono in: $RESULTS_DIR${RESET}\n"
    press_enter
}

# ── Utility ────────────────────────────────────────────────────────────────────
press_enter() {
    echo -ne "  ${GRAY}Premi INVIO per tornare al menu...${RESET}"
    read -r
}

# =============================================================================
# LOOP PRINCIPALE
# =============================================================================
while true; do
    print_banner
    print_menu

    echo -ne "  ${WHITE}${BOLD}Scelta:${RESET} "
    read -r CHOICE

    case "$CHOICE" in
        1) run_scan_static ;;
        2) run_scan_nvd ;;
        3) run_scan_full_ai ;;
        0)
            echo -e "\n  ${GRAY}Uscita. Buona analisi.${RESET}\n"
            exit 0
            ;;
        *)
            echo -e "\n  ${RED}Scelta non valida.${RESET}"
            sleep 1
            ;;
    esac
done
