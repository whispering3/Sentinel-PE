# Mapeamento de requisitos

O manual-base de 55 módulos é a especificação funcional do Sentinel PE. Esta página converte os temas didáticos em entregas de produto defensivas.

| Área do manual | Capacidades da ferramenta | Estado |
| --- | --- | --- |
| PE e arquitetura Windows | Identificar PE, arquitetura, headers, entry point e seções. | Implementado |
| Hashes e triagem | Calcular SHA-256 e exibir metadados básicos. | Implementado |
| Imports e strings | Listar DLLs importadas e strings ASCII. | Implementado |
| Relatórios técnicos | Exportar descobertas com evidência e nível de confiança. | Parcial: JSON |
| Indicadores e detecção | Produzir IOCs e sugestões explicáveis de YARA/Sigma. | Parcial: hash e IOCs textuais |
| Forense e timeline | Importar artefatos autorizados e correlacionar eventos. | Parcial: JSON normalizado |
| Análise dinâmica | Integrar dados de laboratório sem executar amostras no aplicativo. | Planejado |

## Princípios de implementação

1. Processamento local por padrão.
2. Nenhuma execução de binários pela aplicação.
3. Separação entre fato observado, inferência e hipótese.
4. Funcionalidades defensivas, auditáveis e reproduzíveis.
5. Integrações externas somente com consentimento explícito do analista.

## Prioridade técnica

1. Exportação de relatório JSON/Markdown.
2. Parser de exports, resources e data directories.
3. Heurísticas transparentes baseadas em metadados PE.
4. Empacotamento instalável para Windows.

O manual-base permanece em [`../readme`](../readme) como referência de domínio e escopo.
