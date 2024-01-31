;(function() {
    var selem = document.currentScript;
  
    var button = document.createElement('button');
    button.className = "dupl-auth-button";
    button.textContent = (selem.attributes.text || {value: 'Login With Dupl Auth'}).value;
  
    if (location.protocol !== 'https:') {
      var err = document.createElement('div');
      err.className = "dupl-auth-error";
      err.textContent = 'Dupl Auth requires https!';
      selem.parentNode.insertBefore(err, selem);
    }
  
    button.onclick = function() {
      // var authWindow = window.open('https://replit.com/auth_with_repl_site?domain=' + location.host)
      window.addEventListener('message', authComplete);
  
      var h = 500;
          var w = 350;
          var left = (screen.width / 2) - ( w / 2);
          var top = (screen.height / 2) - (h / 2);
  
      var authWindow = window.open(
        'https://auth.marcusj.org/auth/'+location.host,
        '_blank',
        'modal =yes, toolbar=no, location=no, directories=no, status=no, menubar=no, scrollbars=no, resizable=no, copyhistory=no, width='+w+', height='+h+', top='+top+', left='+left)
  
      function authComplete(e) {
  
        window.removeEventListener('message', authComplete);
  
        authWindow.close();
        if (selem.attributes.authed.value) {
          eval(selem.attributes.authed.value)(e.data)
        } else {
          alert(e.data);
        }
      }
    }
  
    selem.parentNode.insertBefore(button, selem);
  })();