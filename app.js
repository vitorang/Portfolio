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

function renderizar(dados, autenticado) {
    const lateral = dados.lateral || {};
    const conteudo = dados.conteudo || {};

    const userNameEl = document.getElementById('userName');
    const userRoleEl = document.getElementById('userRole');

    let nomeExibicao = '';
    if (lateral.nome) {
        if (typeof lateral.nome === 'string') nomeExibicao = lateral.nome;
        else if (typeof lateral.nome.valor === 'string') nomeExibicao = lateral.nome.valor;
    }

    if (userNameEl) {
        userNameEl.textContent = nomeExibicao || lateral.usuarioGithub;
    }

    if (userRoleEl && lateral.cargo) {
        userRoleEl.textContent = lateral.cargo;
    }

    const sobre = conteudo.sobre || {};
    const bioText = document.getElementById('bioText');
    if (bioText && sobre.biografia) {
        bioText.textContent = sobre.biografia.trim();
    }

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
                let iconePath = 'assets/bookmark.svg';
                let linkHtml = c.textoExibicao || c.valor;

                if (tipoLower.includes('whatsapp')) {
                    iconePath = 'assets/whatsapp.svg';
                    const num = String(c.valor).replace(/\D/g, '');
                    linkHtml = `<a href="https://wa.me/${num}" target="_blank" rel="noopener noreferrer">${c.valor}</a>`;
                } else if (tipoLower.includes('email') || tipoLower.includes('e-mail')) {
                    iconePath = 'assets/envelope.svg';
                    linkHtml = `<a href="mailto:${c.valor}">${c.valor}</a>`;
                } else if (tipoLower.includes('local')) {
                    iconePath = 'assets/location-dot.svg';
                    linkHtml = `<span>${c.valor}</span>`;
                } else if (tipoLower.includes('github')) {
                    iconePath = 'assets/github.svg';
                    const usuario = c.valor.replace(/^https?:\/\/(www\.)?github\.com\//i, '').replace(/\/$/, '');
                    linkHtml = `<a href="${c.valor}" target="_blank" rel="noopener noreferrer">${usuario}</a>`;
                } else if (tipoLower.includes('linkedin')) {
                    iconePath = 'assets/linkedin.svg';
                    const perfil = c.valor.replace(/^https?:\/\/(www\.)?linkedin\.com\/(in\/)?/i, '').replace(/\/$/, '');
                    linkHtml = `<a href="${c.valor}" target="_blank" rel="noopener noreferrer">${perfil}</a>`;
                } else if (String(c.valor).startsWith('http')) {
                    linkHtml = `<a href="${c.valor}" target="_blank" rel="noopener noreferrer">${c.valor.replace(/^https?:\/\/(www\.)?/, '')}</a>`;
                }

                const tipoClasse = tipoLower.replace(/[^a-z0-9]/g, '');

                return `
          <div class="contact-row contact-${tipoClasse}">
            <span class="contact-icon" style="--icon-url: url('${iconePath}');" aria-hidden="true"></span>
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
        expList.innerHTML = itensExp.map(exp => {
            const tags = (exp.tecnologias || []).map(t => `<span class="tag">${t}</span>`).join('');

            return `
        <article class="content-item">
          <div class="item-header">
            <div class="item-role-group">
              <span class="item-role">${exp.cargo}</span>
              <span class="role-separator" style="color: var(--text-muted);">–</span>
              <span class="item-company">${exp.empresa}</span>
            </div>
            <span class="item-period">${exp.periodo}</span>
          </div>
          ${tags ? `<div class="tags-row">${tags}</div>` : ''}
          <p class="item-desc">${exp.descricao.trim()}</p>
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

    let textoGlobal = '';
    if (typeof conteudo.projetos?.texto === 'string') textoGlobal = conteudo.projetos.texto;
    else if (typeof conteudo.projetos?.texto?.valor === 'string') textoGlobal = conteudo.projetos.texto.valor;
    else if (typeof conteudo.projetos?.nota === 'string') textoGlobal = conteudo.projetos.nota;
    else if (typeof conteudo.projetos?.nota?.valor === 'string') textoGlobal = conteudo.projetos.nota.valor;

    if (globalNoteEl) {
        if (textoGlobal) {
            globalNoteEl.innerHTML = `<p class="project-desc" style="margin-bottom: 24px;">${textoGlobal.trim()}</p>`;
        } else {
            globalNoteEl.innerHTML = '';
        }
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

    renderizar(dadosFinais, autenticado);

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
}

if (document.readyState === 'complete') {
    iniciar();
} else {
    window.addEventListener('load', iniciar);
}
