var css = document.createElement('link');
css.rel = 'stylesheet';
css.href = '/static/loader.css';
document.body.appendChild(css);

function addLoader(elm) {
    elm.innerHTML += `<svg class="spinner" width="65px" height="65px" viewBox="0 0 66 66" xmlns="http://www.w3.org/2000/svg">
   <circle class="path" stroke="#6121ff" fill="none" stroke-width="4" stroke-linecap="round" cx="33" cy="33" r="30"></circle>
	</svg>
	<svg class="spinner2" width="65px" height="65px" viewBox="0 0 66 66" xmlns="http://www.w3.org/2000/svg">
		<circle class="path" stroke="#6121ff" fill="none" stroke-width="4" stroke-linecap="round" cx="33" cy="33" r="30"></circle>
	</svg>`
}