function base64ToArrayBuffer(base64) {
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

async function derivarChave(senha, saltBuffer) {
    const enc = new TextEncoder();
    const rawKey = enc.encode(senha);

    const keyMaterial = await window.crypto.subtle.importKey(
        'raw',
        rawKey,
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
    );

    return await window.crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: saltBuffer,
            iterations: 100000,
            hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
    );
}

async function descriptografarBloco(blocoCifrado, senha) {
    try {
        const saltBuffer = base64ToArrayBuffer(blocoCifrado.salt);
        const ivBuffer = base64ToArrayBuffer(blocoCifrado.iv);
        const dadosBuffer = base64ToArrayBuffer(blocoCifrado.dados);

        const chave = await derivarChave(senha, saltBuffer);

        const decryptedBuffer = await window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: ivBuffer },
            chave,
            dadosBuffer
        );

        const dec = new TextDecoder();
        return dec.decode(decryptedBuffer);
    } catch {
        return null;
    }
}

async function descriptografarObjeto(obj, senha) {
    if (!obj || typeof obj !== 'object') return obj;

    if (obj.__cifrado === true && obj.dados && obj.iv && obj.salt) {
        const texto = await descriptografarBloco(obj, senha);
        if (texto !== null) {
            try {
                return JSON.parse(texto);
            } catch {
                return texto;
            }
        }
        return null;
    }

    if (Array.isArray(obj)) {
        const arr = [];
        for (const item of obj) {
            const dec = await descriptografarObjeto(item, senha);
            if (dec !== null) arr.push(dec);
        }
        return arr;
    }

    const resultado = {};
    for (const [k, v] of Object.entries(obj)) {
        const dec = await descriptografarObjeto(v, senha);
        if (dec !== null) {
            resultado[k] = dec;
        }
    }
    return resultado;
}

function renderizar(dados, autenticado, chave) {
    const lateral = dados.lateral || {};
    const conteudo = dados.conteudo || {};

    const userNameEl = document.getElementById('userName');
    const userRoleEl = document.getElementById('userRole');

    let nomeExibicao = '';
    if (lateral.nome) {
        if (typeof lateral.nome === 'string') nomeExibicao = lateral.nome;
        else if (typeof lateral.nome.valor === 'string') nomeExibicao = lateral.nome.valor;
    }

    let nomePdfExibicao = '';
    if (lateral.nomePdf) {
        if (typeof lateral.nomePdf === 'string') nomePdfExibicao = lateral.nomePdf;
        else if (typeof lateral.nomePdf.valor === 'string') nomePdfExibicao = lateral.nomePdf.valor;
    }

    if (userNameEl) {
        const nomePrincipal = nomeExibicao || lateral.usuarioGithub || 'Portfólio';
        const nomePdfFinal = nomePdfExibicao || nomePrincipal;

        userNameEl.innerHTML = `
            <span class="name-web">${nomePrincipal}</span>
            <span class="name-pdf">${nomePdfFinal}</span>
        `;
    }

    if (userRoleEl && lateral.cargo) {
        const cargoPrincipal = lateral.cargo;
        const cargoPdfFinal = lateral.cargoPdf || cargoPrincipal;

        userRoleEl.innerHTML = `
            <span class="role-web">${cargoPrincipal}</span>
            <span class="role-pdf">${cargoPdfFinal}</span>
        `;
    }

    const sobre = conteudo.sobre || {};
    const bioText = document.getElementById('bioText');
    if (bioText && sobre.biografia) {
        bioText.textContent = sobre.biografia.trim();
    }

    const ICONS = {
        whatsapp: `<svg viewBox="0 0 640 640" class="contact-icon" aria-hidden="true"><path d="M476.9 161.1C435 119.1 379.2 96 319.9 96C197.5 96 97.9 195.6 97.9 318C97.9 357.1 108.1 395.3 127.5 429L96 544L213.7 513.1C246.1 530.8 282.6 540.1 319.8 540.1L319.9 540.1C442.2 540.1 544 440.5 544 318.1C544 258.8 518.8 203.1 476.9 161.1zM319.9 502.7C286.7 502.7 254.2 493.8 225.9 477L219.2 473L149.4 491.3L168 423.2L163.6 416.2C145.1 386.8 135.4 352.9 135.4 318C135.4 216.3 218.2 133.5 320 133.5C369.3 133.5 415.6 152.7 450.4 187.6C485.2 222.5 506.6 268.8 506.5 318.1C506.5 419.9 421.6 502.7 319.9 502.7zM421.1 364.5C415.6 361.7 388.3 348.3 383.2 346.5C378.1 344.6 374.4 343.7 370.7 349.3C367 354.9 356.4 367.3 353.1 371.1C349.9 374.8 346.6 375.3 341.1 372.5C308.5 356.2 287.1 343.4 265.6 306.5C259.9 296.7 271.3 297.4 281.9 276.2C283.7 272.5 282.8 269.3 281.4 266.5C280 263.7 268.9 236.4 264.3 225.3C259.8 214.5 255.2 216 251.8 215.8C248.6 215.6 244.9 215.6 241.2 215.6C237.5 215.6 231.5 217 226.4 222.5C221.3 228.1 207 241.5 207 268.8C207 296.1 226.9 322.5 229.6 326.2C232.4 329.9 268.7 385.9 324.4 410C359.6 425.2 373.4 426.5 391 423.9C401.7 422.3 423.8 410.5 428.4 397.5C433 384.5 433 373.4 431.6 371.1C430.3 368.6 426.6 367.2 421.1 364.5z"/></svg>`,
        email: `<svg viewBox="0 0 640 640" class="contact-icon" aria-hidden="true"><path d="M125.4 128C91.5 128 64 155.5 64 189.4C64 190.3 64 191.1 64.1 192L64 192L64 448C64 483.3 92.7 512 128 512L512 512C547.3 512 576 483.3 576 448L576 192L575.9 192C575.9 191.1 576 190.3 576 189.4C576 155.5 548.5 128 514.6 128L125.4 128zM528 256.3L528 448C528 456.8 520.8 464 512 464L128 464C119.2 464 112 456.8 112 448L112 256.3L266.8 373.7C298.2 397.6 341.7 397.6 373.2 373.7L528 256.3zM112 189.4C112 182 118 176 125.4 176L514.6 176C522 176 528 182 528 189.4C528 193.6 526 197.6 522.7 200.1L344.2 335.5C329.9 346.3 310.1 346.3 295.8 335.5L117.3 200.1C114 197.6 112 193.6 112 189.4z"/></svg>`,
        local: `<svg viewBox="0 0 640 640" class="contact-icon" aria-hidden="true"><path d="M128 252.6C128 148.4 214 64 320 64C426 64 512 148.4 512 252.6C512 371.9 391.8 514.9 341.6 569.4C329.8 582.2 310.1 582.2 298.3 569.4C248.1 514.9 127.9 371.9 127.9 252.6zM320 320C355.3 320 384 291.3 384 256C384 220.7 355.3 192 320 192C284.7 192 256 220.7 256 256C256 291.3 284.7 320 320 320z"/></svg>`,
        github: `<svg viewBox="0 0 640 640" class="contact-icon" aria-hidden="true"><path d="M237.9 461.4C237.9 463.4 235.6 465 232.7 465C229.4 465.3 227.1 463.7 227.1 461.4C227.1 459.4 229.4 457.8 232.3 457.8C235.3 457.5 237.9 459.1 237.9 461.4zM206.8 456.9C206.1 458.9 208.1 461.2 211.1 461.8C213.7 462.8 216.7 461.8 217.3 459.8C217.9 457.8 216 455.5 213 454.6C210.4 453.9 207.5 454.9 206.8 456.9zM251 455.2C248.1 455.9 246.1 457.8 246.4 460.1C246.7 462.1 249.3 463.4 252.3 462.7C255.2 462 257.2 460.1 256.9 458.1C256.6 456.2 253.9 454.9 251 455.2zM316.8 72C178.1 72 72 177.3 72 316C72 426.9 141.8 521.8 241.5 555.2C254.3 557.5 258.8 549.6 258.8 543.1C258.8 536.9 258.5 502.7 258.5 481.7C258.5 481.7 188.5 496.7 173.8 451.9C173.8 451.9 162.4 422.8 146 415.3C146 415.3 123.1 399.6 147.6 399.9C147.6 399.9 172.5 401.9 186.2 425.7C208.1 464.3 244.8 453.2 259.1 446.6C261.4 430.6 267.9 419.5 275.1 412.9C219.2 406.7 162.8 398.6 162.8 302.4C162.8 274.9 170.4 261.1 186.4 243.5C183.8 237 175.3 210.2 189 175.6C209.9 169.1 258 202.6 258 202.6C278 197 299.5 194.1 320.8 194.1C342.1 194.1 363.6 197 383.6 202.6C383.6 202.6 431.7 169 452.6 175.6C466.3 210.3 457.8 237 455.2 243.5C471.2 261.2 481 275 481 302.4C481 398.9 422.1 406.6 366.2 412.9C375.4 420.8 383.2 435.8 383.2 459.3C383.2 493 382.9 534.7 382.9 542.9C382.9 549.4 387.5 557.3 400.2 555C500.2 521.8 568 426.9 568 316C568 177.3 455.5 72 316.8 72zM169.2 416.9C167.9 417.9 168.2 420.2 169.9 422.1C171.5 423.7 173.8 424.4 175.1 423.1C176.4 422.1 176.1 419.8 174.4 417.9C172.8 416.3 170.5 415.6 169.2 416.9zM158.4 408.8C157.7 410.1 158.7 411.7 160.7 412.7C162.3 413.7 164.3 413.4 165 412C165.7 410.7 164.7 409.1 162.7 408.1C160.7 407.5 159.1 407.8 158.4 408.8zM190.8 444.4C189.2 445.7 189.8 448.7 192.1 450.6C194.4 452.9 197.3 453.2 198.6 451.6C199.9 450.3 199.3 447.3 197.3 445.4C195.1 443.1 192.1 442.8 190.8 444.4zM179.4 429.7C177.8 430.7 177.8 433.3 179.4 435.6C181 437.9 183.7 438.9 185 437.9C186.6 436.6 186.6 434 185 431.7C183.6 429.4 181 428.4 179.4 429.7z"/></svg>`,
        default: `<svg viewBox="0 0 640 640" class="contact-icon" aria-hidden="true"><path d="M128 64C92.7 64 64 92.7 64 128L64 512c0 23.6 13 45.2 33.8 56.2s46.1 9.6 65.7-3.7L320 457.1 476.5 564.5c19.6 13.3 44.9 14.7 65.7 3.7S576 535.6 576 512l0-384c0-35.3-28.7-64-64-64L128 64z"/></svg>`
    };

    const contactsList = document.getElementById('contactsList');
    if (contactsList) {
        const listaContatos = Array.isArray(sobre.contatos) ? sobre.contatos : [];

        if (listaContatos.length === 0) {
            contactsList.style.display = 'none';
            contactsList.innerHTML = '';
        } else {
            contactsList.style.display = 'flex';
            contactsList.innerHTML = listaContatos.map(c => {
                const tipoLower = (c.tipo || '').toLowerCase();
                let svgHtml = ICONS.default;
                let linkHtml = c.textoExibicao || c.valor;

                if (tipoLower.includes('whatsapp')) {
                    svgHtml = ICONS.whatsapp;
                    const num = String(c.valor).replace(/\D/g, '');
                    linkHtml = `<a href="https://wa.me/${num}" target="_blank" rel="noopener noreferrer">${c.valor}</a>`;
                } else if (tipoLower.includes('email') || tipoLower.includes('e-mail')) {
                    svgHtml = ICONS.email;
                    linkHtml = `<a href="mailto:${c.valor}">${c.valor}</a>`;
                } else if (tipoLower.includes('local')) {
                    svgHtml = ICONS.local;
                    linkHtml = `<span>${c.valor}</span>`;
                } else if (tipoLower.includes('github')) {
                    svgHtml = ICONS.github;
                    const usuario = c.valor.replace(/^https?:\/\/(www\.)?github\.com\//i, '').replace(/\/$/, '');
                    linkHtml = `<a href="${c.valor}" target="_blank" rel="noopener noreferrer">${usuario}</a>`;
                } else if (String(c.valor).startsWith('http')) {
                    linkHtml = `<a href="${c.valor}" target="_blank" rel="noopener noreferrer">${c.valor.replace(/^https?:\/\/(www\.)?/, '')}</a>`;
                }

                const tipoClasse = tipoLower.replace(/[^a-z0-9]/g, '');

                return `
          <div class="contact-row contact-${tipoClasse}">
            ${svgHtml}
            <span class="contact-value">${linkHtml}</span>
          </div>
        `;
            }).join('');
        }
    }

    const expSection = document.getElementById('experiencias');
    const expList = document.getElementById('experienceList');
    const itensExp = Array.isArray(conteudo.experiencias) ? conteudo.experiencias : [];

    if (expSection) {
        expSection.style.display = itensExp.length > 0 ? '' : 'none';
    }

    if (expList && itensExp.length > 0) {
        const baseUrl = lateral.portfolioGithub;

        expList.innerHTML = itensExp.map(exp => {
            const tags = (exp.tecnologias || []).map(t => `<span class="tag">${t}</span>`).join('');

            const empresaHtml = exp.empresa ? `
              <span class="role-separator" style="color: var(--text-muted);">–</span>
              <span class="item-company">${exp.empresa}</span>` : '';

            let pdfLinkHtml = '';
            if (exp.notaPdf) {
                let textoNota = String(exp.notaPdf);
                // Substitui [GITHUB#ancora] ou [GITHUB]
                textoNota = textoNota.replace(/\[GITHUB(?:#([a-zA-Z0-9_-]+))?\]/g, (match, ancora) => {
                    const hash = ancora ? `#${ancora}` : '';
                    const fullUrl = chave ? `${baseUrl}?k=${encodeURIComponent(chave)}${hash}` : `${baseUrl}${hash}`;
                    const displayUrl = chave ? `${baseUrl}?k=${chave}` : baseUrl;
                    return `<a href="${fullUrl}" target="_blank" rel="noopener noreferrer">${displayUrl}</a>`;
                });
                pdfLinkHtml = `<p class="project-pdf-link">${textoNota}</p>`;
            }

            return `
        <article class="content-item">
          <div class="item-header">
            <div class="item-role-group">
              <span class="item-role">${exp.cargo}</span>${empresaHtml}
            </div>
            <span class="item-period">${exp.periodo}</span>
          </div>
          ${tags ? `<div class="tags-row">${tags}</div>` : ''}
          ${(exp.descricao || '').trim().split('\n').filter(l => l.trim().length > 0).map(paragrafo => `<p class="item-desc">${paragrafo.trim()}</p>`).join('')}
          ${pdfLinkHtml}
        </article>
      `;
        }).join('');
    }

    const formSection = document.getElementById('formacao');
    const eduList = document.getElementById('educationList');
    const itensForm = Array.isArray(conteudo.formacao) ? conteudo.formacao : [];

    if (formSection) {
        formSection.style.display = itensForm.length > 0 ? '' : 'none';
    }

    if (eduList && itensForm.length > 0) {
        eduList.innerHTML = itensForm.map(f => `
      <article class="content-item">
        <div class="item-header">
          <div class="item-role-group">
            <span class="item-role">${f.curso}</span>
            <span class="role-separator" style="color: var(--text-muted);">–</span>
            <span class="item-company">${f.instituicao}</span>
          </div>
          <span class="item-period">${f.periodo}</span>
        </div>
        ${f.descricao ? `<p class="item-desc">${f.descricao.trim()}</p>` : ''}
      </article>
    `).join('');
    }

    const skillsContainer = document.getElementById('skillsContainer');
    if (skillsContainer && conteudo.habilidades) {
        const colA = conteudo.habilidades.filter(h => (h.coluna || 'a').toLowerCase() === 'a');
        const colB = conteudo.habilidades.filter(h => (h.coluna || '').toLowerCase() === 'b');

        const renderGrupo = (grupo) => grupo.map(cat => `
      <div class="skill-block">
        <h3 class="skill-block-title">${cat.categoria}</h3>
        <ul class="skill-list">
          ${(cat.itens || []).map(item => `<li class="skill-list-item">${item}</li>`).join('')}
        </ul>
      </div>
    `).join('');

        skillsContainer.innerHTML = `
      <div class="skills-column skills-col-a">
        ${renderGrupo(colA)}
      </div>
      <div class="skills-column skills-col-b">
        ${renderGrupo(colB)}
      </div>
    `;
    }

    const projContainer = document.getElementById('projectList');
    const globalNoteEl = document.getElementById('projectGlobalNote');
    if (globalNoteEl) {
        globalNoteEl.remove();
    }

    if (projContainer && conteudo.projetos?.itens) {
        projContainer.innerHTML = conteudo.projetos.itens.map(proj => {
            let notaProj = '';
            if (typeof proj.nota === 'string') notaProj = proj.nota;
            else if (typeof proj.nota?.valor === 'string') notaProj = proj.nota.valor;

            let demoUrl = '';
            if (typeof proj.links?.demonstracao === 'string') demoUrl = proj.links.demonstracao;
            else if (typeof proj.links?.demonstracao?.valor === 'string') demoUrl = proj.links.demonstracao.valor;

            const links = [];
            if (proj.links?.github) {
                links.push(`<a href="${proj.links.github}" class="btn-project btn-outline" target="_blank" rel="noopener noreferrer">Repositório GitHub</a>`);
            }
            if (demoUrl) {
                links.push(`<a href="${demoUrl}" class="btn-project btn-primary" target="_blank" rel="noopener noreferrer">Acessar Demonstração</a>`);
            }

            const tags = (proj.tecnologias || []).map(t => `<span class="tag">${t}</span>`).join('');

            return `
        <article class="project-item">
          <h3 class="project-name">${proj.nome}</h3>
          ${tags ? `<div class="tags-row">${tags}</div>` : ''}
          <p class="project-desc">${proj.descricao.trim()}</p>
          ${notaProj ? `<div class="project-note">${notaProj.trim()}</div>` : ''}
          ${links.length ? `<div class="project-links">${links.join('')}</div>` : ''}
        </article>
      `;
        }).join('');
    }
}

async function iniciar() {
    const params = new URLSearchParams(window.location.search);
    const chave = params.get('k');
    let autenticado = false;
    const dadosIniciais = window.DADOS || {};
    let dadosFinais = dadosIniciais;

    if (chave && chave.trim().length > 0) {
        try {
            const dec = await descriptografarObjeto(dadosIniciais, chave.trim());
            if (dec?.lateral?.nome) {
                autenticado = true;
                dadosFinais = dec;
            }
        } catch {
        }
    }

    renderizar(dadosFinais, autenticado, chave ? chave.trim() : '');

    const avatarImg = document.getElementById('userAvatar');
    if (avatarImg) {
        const avatarSrc = dadosFinais?.lateral?.avatar || '';
        if (avatarSrc) {
            avatarImg.src = avatarSrc;
        }
    }

    if (document.fonts) {
        await document.fonts.ready;
    }

    const container = document.querySelector('.app-container');
    if (container) container.classList.remove('hidden');

    if (window.location.hash) {
        const targetId = window.location.hash.substring(1);
        const targetEl = document.getElementById(targetId);
        if (targetEl) {
            requestAnimationFrame(() => {
                targetEl.scrollIntoView({ behavior: 'smooth' });
            });
        }
    }
}

if (document.readyState === 'complete') {
    iniciar();
} else {
    window.addEventListener('load', iniciar);
}
