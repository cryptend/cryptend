function togglePrivateKey(btn) {
  const privateKey = document.getElementById('privateKey');
  if (privateKey.type === 'password') {
    privateKey.type = 'text';
    btn.innerText = 'hide';
  } else {
    privateKey.type = 'password';
    btn.innerText = 'show';
  }
}

const privateKeyToggle = document.getElementById('privateKeyToggle');
if (privateKeyToggle) {
  privateKeyToggle.addEventListener('click', (e) => togglePrivateKey(e.target));
}

function copyText(inputId, btn) {
  const input = document.getElementById(inputId);
  if (input.value) {
    navigator.clipboard.writeText(input.value).then(() => {
      const btnText = btn.innerText;
      btn.innerText = 'Copied';
      setTimeout(() => {
        btn.innerText = btnText;
      }, 1000);
    });
  }
}

const copyPrivateKey = document.getElementById('copyPrivateKey');
if (copyPrivateKey) {
  copyPrivateKey.addEventListener('click', (e) => copyText('privateKey', e.target));
}

const copyPublicKey = document.getElementById('copyPublicKey');
if (copyPublicKey) {
  copyPublicKey.addEventListener('click', (e) => copyText('publicKey', e.target));
}

const copyEncrypted = document.getElementById('copyEncrypted');
if (copyEncrypted) {
  copyEncrypted.addEventListener('click', (e) => copyText('encrypted', e.target));
}

if (!['/', '/1', '/2'].includes(window.location.pathname)) {
  window.scrollTo(0, document.body.scrollHeight);
  document.querySelectorAll('.created-at').forEach((el) => {
    const createdAt = new Date(el.innerText);
    const createdAtTime = createdAt.toLocaleTimeString();
    const timeArray = createdAtTime.split(':');
    let timeShort = `${timeArray[0]}:${timeArray[1]}`;
    if (timeArray[2].includes(' ')) {
      timeShort += ` ${timeArray[2].split(' ')[1]}`;
    }
    el.innerText = timeShort;
    el.setAttribute('data-tip', createdAt.toLocaleString());
  });
}