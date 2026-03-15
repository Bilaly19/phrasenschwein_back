const { AppError } = require('../utils/http');

function normalizeUsername(username) {
  return typeof username === 'string' ? username.trim().toLowerCase() : '';
}

function toFiniteNumber(value, fallback = 0) {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : fallback;
}

function extractClicks(entry) {
  return Number(entry?.clicks ?? entry?.count) || 0;
}

function sanitizeHistory(history, maxItems) {
  if (!Array.isArray(history)) return [];

  return history
    .filter((item) => item && typeof item === 'object')
    .map((item) => {
      const role = item.role === 'assistant' ? 'assistant' : (item.role === 'user' ? 'user' : null);
      const content = typeof item.content === 'string' ? item.content.trim() : '';
      if (!role || !content) return null;
      return {
        role,
        content: content.slice(0, 2000)
      };
    })
    .filter(Boolean)
    .slice(-maxItems);
}

function extractReplyContent(rawContent) {
  if (typeof rawContent === 'string') {
    return rawContent.trim();
  }

  if (!Array.isArray(rawContent)) {
    return '';
  }

  return rawContent
    .map((chunk) => {
      if (!chunk || typeof chunk !== 'object') return '';
      if (chunk.type === 'text' && typeof chunk.text === 'string') return chunk.text;
      return '';
    })
    .join('\n')
    .trim();
}

class AssistantService {
  constructor({ config, pigsService, fetchImpl = fetch }) {
    this.pigsService = pigsService;
    this.fetchImpl = fetchImpl;
    this.openaiApiKey = config?.openaiApiKey || '';
    this.openaiModel = config?.openaiModel || 'gpt-4o-mini';
    this.openaiBaseUrl = (config?.openaiBaseUrl || 'https://api.openai.com/v1').replace(/\/+$/, '');
    this.openaiTimeoutMs = toFiniteNumber(config?.openaiTimeoutMs, 20000);
    this.assistantMaxHistory = Number.isInteger(config?.assistantMaxHistory) ? config.assistantMaxHistory : 8;
    this.assistantMaxPigs = Number.isInteger(config?.assistantMaxPigs) ? config.assistantMaxPigs : 12;
  }

  isConfigured() {
    return Boolean(this.openaiApiKey);
  }

  async buildPortfolioSummary(actor) {
    const username = normalizeUsername(actor?.username);
    const pigs = await this.pigsService.listPigs(username);
    const limitedPigs = pigs.slice(0, this.assistantMaxPigs);

    const pigSummaries = await Promise.all(
      limitedPigs.map(async (pig) => {
        const [names, config] = await Promise.all([
          this.pigsService.getPigNamesByActor(actor, pig.id),
          this.pigsService.getPigConfigByActor(actor, pig.id)
        ]);

        const valuePerClick = toFiniteNumber(config?.valuePerClick, toFiniteNumber(pig?.valuePerClick, 0.5));
        const members = Object.entries(names || {})
          .filter(([, entry]) => entry && typeof entry === 'object')
          .map(([memberName, entry]) => {
            const clicks = extractClicks(entry);
            return {
              name: memberName,
              clicks,
              amount: Number((clicks * valuePerClick).toFixed(2))
            };
          })
          .sort((a, b) => b.clicks - a.clicks || a.name.localeCompare(b.name));

        const totalClicks = members.reduce((sum, member) => sum + member.clicks, 0);
        const totalAmount = Number((totalClicks * valuePerClick).toFixed(2));
        const own = members.find((member) => member.name === username) || { clicks: 0, amount: 0 };

        return {
          id: pig.id,
          title: pig.title || 'Phrasenschwein',
          role: pig.role || 'member',
          valuePerClick: Number(valuePerClick.toFixed(2)),
          memberCount: members.length,
          totalClicks,
          totalAmount,
          ownClicks: own.clicks,
          ownAmount: own.amount,
          topMembers: members.slice(0, 3)
        };
      })
    );

    const totalClicks = pigSummaries.reduce((sum, pig) => sum + pig.totalClicks, 0);
    const totalAmount = Number(pigSummaries.reduce((sum, pig) => sum + pig.totalAmount, 0).toFixed(2));

    return {
      generatedAt: new Date().toISOString(),
      pigCount: pigs.length,
      includedPigCount: pigSummaries.length,
      totalClicks,
      totalAmount,
      pigs: pigSummaries
    };
  }

  async requestOpenAi(messages) {
    const controller = new AbortController();
    const timeoutHandle = setTimeout(() => controller.abort(), this.openaiTimeoutMs);

    try {
      const response = await this.fetchImpl(`${this.openaiBaseUrl}/chat/completions`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${this.openaiApiKey}`
        },
        body: JSON.stringify({
          model: this.openaiModel,
          messages,
          temperature: 0.35,
          max_tokens: 500
        }),
        signal: controller.signal
      });

      let payload = null;
      try {
        payload = await response.json();
      } catch {
        payload = null;
      }

      if (!response.ok) {
        throw new AppError(
          502,
          'ASSISTANT_UPSTREAM_ERROR',
          `KI-Anbieter Fehler (HTTP ${response.status}).`,
          [{ path: 'upstreamStatus', message: String(response.status) }]
        );
      }

      const reply = extractReplyContent(payload?.choices?.[0]?.message?.content);
      if (!reply) {
        throw new AppError(502, 'ASSISTANT_EMPTY_RESPONSE', 'KI-Antwort war leer.');
      }

      return {
        reply,
        model: payload?.model || this.openaiModel
      };
    } catch (error) {
      if (error?.name === 'AbortError') {
        throw new AppError(504, 'ASSISTANT_TIMEOUT', 'KI-Antwort hat zu lange gedauert.');
      }

      if (error instanceof AppError) {
        throw error;
      }

      throw new AppError(502, 'ASSISTANT_UPSTREAM_ERROR', 'KI-Antwort konnte nicht geladen werden.');
    } finally {
      clearTimeout(timeoutHandle);
    }
  }

  toPortfolioMeta(portfolioSummary) {
    if (!portfolioSummary) return null;
    return {
      pigCount: portfolioSummary.pigCount,
      includedPigCount: portfolioSummary.includedPigCount,
      totalClicks: portfolioSummary.totalClicks,
      totalAmount: portfolioSummary.totalAmount
    };
  }

  extractUpstreamStatus(error) {
    const details = Array.isArray(error?.details) ? error.details : [];
    const statusDetail = details.find((item) => item?.path === 'upstreamStatus');
    const statusFromDetails = Number(statusDetail?.message);
    if (Number.isInteger(statusFromDetails)) {
      return statusFromDetails;
    }

    const match = String(error?.message || '').match(/HTTP (\d{3})/);
    if (!match) return null;
    const statusFromMessage = Number(match[1]);
    return Number.isInteger(statusFromMessage) ? statusFromMessage : null;
  }

  shouldUseLocalFallback(error) {
    if (!(error instanceof AppError)) return false;
    return (
      error.code === 'ASSISTANT_UPSTREAM_ERROR'
      || error.code === 'ASSISTANT_TIMEOUT'
      || error.code === 'ASSISTANT_EMPTY_RESPONSE'
    );
  }

  buildLocalReply(message, portfolioSummary, reason = {}) {
    const normalizedMessage = String(message || '').trim();
    const summary = portfolioSummary || {
      pigCount: 0,
      totalClicks: 0,
      totalAmount: 0,
      pigs: []
    };
    const type = reason?.type || 'missing_key';
    const upstreamStatus = Number(reason?.upstreamStatus);
    const hasUpstreamStatus = Number.isInteger(upstreamStatus);

    const topPigs = Array.isArray(summary.pigs)
      ? [...summary.pigs]
        .sort((a, b) => b.totalAmount - a.totalAmount || b.totalClicks - a.totalClicks)
        .slice(0, 3)
      : [];
    const normalizedForIntent = normalizedMessage.toLowerCase();
    const asksForTotalAmount = /(gesamtbetrag|gesamt betrag|insgesamt|summe|offen|betrag|schulde)/.test(normalizedForIntent);
    const asksForClicks = /(klicks?|anzahl|zaehler|zahler)/.test(normalizedForIntent);

    const lines = [];
    if (asksForTotalAmount) {
      lines.push(`Dein aktueller Gesamtbetrag liegt bei ${summary.totalAmount.toFixed(2)} EUR.`);
      lines.push(`Grundlage: ${summary.totalClicks} Klicks in ${summary.pigCount} Boards.`);
    } else if (asksForClicks) {
      lines.push(`Aktuell sind es ${summary.totalClicks} Klicks ueber ${summary.pigCount} Boards.`);
      lines.push(`Daraus ergeben sich ${summary.totalAmount.toFixed(2)} EUR.`);
    } else {
      lines.push(`Ueberblick: ${summary.pigCount} Boards, ${summary.totalClicks} Klicks, ${summary.totalAmount.toFixed(2)} EUR offen.`);
    }

    if (topPigs.length) {
      lines.push('Top-Boards nach Betrag:');
      topPigs.forEach((pig, index) => {
        lines.push(`${index + 1}. ${pig.title}: ${pig.totalClicks} Klicks, ${pig.totalAmount.toFixed(2)} EUR`);
      });
    } else {
      lines.push('Noch keine Board-Daten vorhanden.');
    }

    if (type === 'missing_key') {
      lines.push('Hinweis: Ich antworte im lokalen Modus, weil kein externer KI-Key gesetzt ist.');
      lines.push('Tipp: Setze OPENAI_API_KEY, um den vollen KI-Modus zu aktivieren.');
    } else if (hasUpstreamStatus && upstreamStatus === 429) {
      lines.push('Hinweis: Ich nutze gerade einen lokalen Fallback, weil der KI-Anbieter ausgelastet ist (HTTP 429).');
      lines.push('Tipp: Versuch es in 1-2 Minuten erneut.');
    } else if (hasUpstreamStatus) {
      lines.push(`Hinweis: Ich nutze gerade einen lokalen Fallback, weil der KI-Anbieter nicht verfuegbar ist (HTTP ${upstreamStatus}).`);
      lines.push('Tipp: Versuch es in 1-2 Minuten erneut.');
    } else if (type === 'timeout') {
      lines.push('Hinweis: Ich nutze gerade einen lokalen Fallback, weil die KI-Antwort zu lange gedauert hat.');
      lines.push('Tipp: Versuch es in 1-2 Minuten erneut.');
    } else {
      lines.push('Hinweis: Ich nutze gerade einen lokalen Fallback, weil der KI-Anbieter nicht erreichbar ist.');
      lines.push('Tipp: Versuch es in 1-2 Minuten erneut.');
    }

    return lines.join('\n');
  }

  buildLocalFallbackResult(message, portfolioSummary, reason = {}) {
    return {
      reply: this.buildLocalReply(message, portfolioSummary, reason),
      model: 'local-phrasenagent',
      portfolio: this.toPortfolioMeta(portfolioSummary)
    };
  }

  async chatByActor(actor, payload = {}) {
    const message = typeof payload.message === 'string' ? payload.message.trim() : '';
    if (!message) {
      throw new AppError(400, 'VALIDATION_ERROR', 'Nachricht darf nicht leer sein.', [{ path: 'message', message: 'message darf nicht leer sein' }]);
    }

    const history = sanitizeHistory(payload.history, this.assistantMaxHistory);
    const includePortfolio = payload.includePortfolio !== false;
    const portfolioSummary = includePortfolio ? await this.buildPortfolioSummary(actor) : null;

    if (!this.isConfigured()) {
      return this.buildLocalFallbackResult(message, portfolioSummary, { type: 'missing_key' });
    }

    const messages = [
      {
        role: 'system',
        content: [
          'Du bist der KI-Assistent der App "Phrasenschwein".',
          'Antworte auf Deutsch, konkret und praxisnah.',
          'Wenn sich Fragen auf Board-Daten beziehen, nutze den bereitgestellten Portfolio-Kontext.',
          'Wenn Daten fehlen, sage das transparent und schlage den naechsten sinnvollen Schritt vor.',
          'Keine erfundenen Fakten.'
        ].join(' ')
      }
    ];

    if (portfolioSummary) {
      messages.push({
        role: 'system',
        content: `Portfolio-Kontext (JSON): ${JSON.stringify(portfolioSummary)}`
      });
    }

    messages.push(...history);
    messages.push({ role: 'user', content: message });

    try {
      const response = await this.requestOpenAi(messages);

      return {
        reply: response.reply,
        model: response.model,
        portfolio: this.toPortfolioMeta(portfolioSummary)
      };
    } catch (error) {
      if (this.shouldUseLocalFallback(error)) {
        return this.buildLocalFallbackResult(message, portfolioSummary, {
          type: error.code === 'ASSISTANT_TIMEOUT' ? 'timeout' : 'upstream',
          upstreamStatus: this.extractUpstreamStatus(error)
        });
      }
      throw error;
    }
  }
}

module.exports = {
  AssistantService
};
