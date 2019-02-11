"use strict";StackExchange.mockups=function(){function e(e,t,n,r,i){function o(e,t,n){for(var r=-1,i=-1;;){if(i=t.indexOf(e,i+1),-1==i)break;(0>r||Math.abs(i-n)<Math.abs(i-r))&&(r=i)}return r}return e.replace(new RegExp("<!-- Begin mockup[^>]*? -->\\s*!\\[[^\\]]*\\]\\((http://[^ )]+)[^)]*\\)\\s*<!-- End mockup -->","g"),function(e,a,s){var l={"payload":a.replace(/[^-A-Za-z0-9+&@#\/%?=~_|!:,.;\(\)]/g,""),"pos":o(e,t,s),"len":e.length};return-1===l.pos?e:(i.push(l),e+"\n\n"+n+r+"-"+(i.length-1)+"%")})}function t(){StackExchange.externalEditor.init({"thingName":"mockup","thingFinder":e,"getIframeUrl":function(e){var t="/plugins/mockups/editor";return e&&(t+="?edit="+encodeURIComponent(e)),t},"buttonTooltip":"UI wireframe","buttonImageUrl":"/content/Shared/Balsamiq/wmd-mockup-button.png","onShow":function(e){window.addMockupToEditor=e},"onRemove":function(){window.addMockupToEditor=null;try{delete window.addMockupToEditor}catch(e){}}})}return{"init":t}}(),StackExchange.schematics=function(){function e(){if(!window.postMessage)return r;var e=document.createElement("div");e.innerHTML="<svg/>";var t="http://www.w3.org/2000/svg"==(e.firstChild&&e.firstChild.namespaceURI);if(!t)return r;var n=navigator.userAgent;return/Firefox|Chrome/.test(n)?a:/Apple/.test(navigator.vendor)||/Opera/.test(n)?o:i}function t(e,t,n,r,i){function o(e,t,n){for(var r=-1,i=-1;;){if(i=t.indexOf(e,i+1),-1==i)break;(0>r||Math.abs(i-n)<Math.abs(i-r))&&(r=i)}return r}return e.replace(new RegExp("<!-- Begin schematic[^>]*? -->\\s*!\\[[^\\]]*\\]\\((http://[^ )]+)[^)]*\\)\\s*<!-- End schematic -->","g"),function(e,a,s){var l={"payload":a.replace(/[^-A-Za-z0-9+&@#\/%?=~_|!:,.;\(\)]/g,""),"pos":o(e,t,s),"len":e.length};return-1===l.pos?e:(i.push(l),e+"\n\n"+n+r+"-"+(i.length-1)+"%")})}function n(){var n;StackExchange.externalEditor.init({"thingName":"schematic","thingFinder":t,"getIframeUrl":function(e){var t="/plugins/schematics/editor";return e&&(t+="?edit="+encodeURIComponent(e)),t},"buttonTooltip":"Schematic","buttonImageUrl":"/content/Sites/electronics/img/wmd-schematic-button.png?v=1","checkSupport":function(){var t=e();switch(t){case a:return!0;case o:return confirm("Your browser is not officially supported by the schematics editor; however it has been reported to work. Launch the editor?");case i:return confirm("Your browser is not officially supported by the schematics editor; it may or may not work. Launch the editor anyway?");case r:return alert("Sorry, your browser does not support all the necessary features for the schematics editor."),!1}},"onShow":function(e){var t=$("<div class='popup' />").css("z-index",1111).text("Loading editor").appendTo("body").show().addSpinner({"marginLeft":5}).center({"dy":-200});$("<div style='text-align:right;margin-top: 10px' />").append($("<button>cancel</button>").click(function(){t.remove(),e()})).appendTo(t),n=function(n){if(n=n.originalEvent,"https://www.circuitlab.com"===n.origin){n.data||e();var r=$.parseJSON(n.data);if(r&&"success"===r.load)return t.remove(),void 0;if(r&&r.edit_url&&r.image_url){r.fkey=StackExchange.options.user.fkey;var i=$("<div class='popup' />").css("z-index",1111).appendTo("body").show(),o=function(){i.text("Storing image").addSpinner({"marginLeft":5}).center(),$.post("/plugins/schematics/save",r).done(function(t){i.remove(),e(t.img)}).fail(function(e){if(409===e.status){var t="Storing aborted";e.responseText.length<200&&(t=e.responseText),i.text(t+", will retry shortly").addSpinner({"marginLeft":5}).center(),setTimeout(o,1e4)}else i.remove(),alert("Failed to upload the schematic image.")})};o()}}},$(window).on("message",n)},"onRemove":function(){$(window).off("message",n)}})}var r=0,i=1,o=2,a=3;return{"init":n}}(),StackExchange.externalEditor=function(){function e(e){function t(e,t){function h(t){function r(){StackExchange.helpers.closePopups(v.add(i)),u()}var i,s=m||b.caret(),l=b[0].value||"",p=t?t.pos:s.start,d=t?t.len:s.end-s.start,h=l.substring(0,p),f=l.substring(p+d);m=null;var g=function(t,i){if(!t)return setTimeout(r,0),b.focus(),void 0;StackExchange.navPrevention.start();var o=void 0===i?n(t):i,a=h.replace(/(?:\r\n|\r|\n){1,2}$/,""),l=a+o+f.replace(/^(?:\r\n|\r|\n){1,2}/,""),c=s.start+o.length-h.length+a.length;setTimeout(function(){e.textOperation(function(){b.val(l).focus().caret(c,c)}),r()},0)},v=null;if(o){var y=o(t?t.payload:null);v=$("<iframe>",{"src":y})}else{var x=a(t?t.payload:null);v=$(x)}v.addClass("esc-remove").css({"position":"fixed","top":"2.5%","left":"2.5%","width":"95%","height":"95%","background":"white","z-index":1001}),$("body").loadPopup({"html":v,"target":$("body"),"lightbox":!0}).done(function(){$(window).resize(),c(g)})}$('<style type="text/css"> .wmd-'+r+"-button span { background-position: 0 0; } .wmd-"+r+"-button:hover span { background-position: 0 -40px; }</style>)").appendTo("head");var f,g,m,v=e.getConverter().hooks,b=$("#wmd-input"+t);b.on("keyup",function(e){var t=e.keyCode||e.charCode;if(8===t||46===t){var n=b.caret().start;b.caret(n,n)}}),v.chain("preConversion",function(e){var t=(e.match(/%/g)||[]).length,n=b.length?b[0].value||"":"";return f=new Array(t+2).join("%"),g=[],i(e,n,f,r,g)}),v.chain("postConversion",function(e){return e.replace(new RegExp(f+r+"-(\\d+)%","g"),function(e,t){return"<sup><a href='#' class='edit-"+r+"' data-id='"+t+"'>"+p+"</a></sup>"})});var y="The "+r+" editor does not support touch devices.",x=!1;$("#wmd-preview"+t).on("touchend",function(){x=!0}).on("click","a.edit-"+r,function(){return x?(alert(y),x=!1,!1):(x=!1,(!d||d())&&h(g[$(this).attr("data-id")]),!1)}),$("#wmd-input"+t).keyup(function(e){e.shiftKey||e.altKey||e.metaKey||!e.ctrlKey||77!==e.which||(!d||d())&&h()}),setTimeout(function(){var e=($("#wmd-button-bar"+t),$("#wmd-image-button"+t)),n=$("<li class='wmd-button wmd-"+r+"-button' id='wmd-"+r+"-button"+t+"' title='"+s+" Ctrl-M' />").insertAfter(e),i=!1,o=$("<span />").css({"backgroundImage":"url("+l+")"}).appendTo(n).on("touchend",function(){i=!0}).click(function(){return i?(alert(y),i=!1,void 0):(i=!1,(!d||d())&&h(),void 0)});$.browser.msie&&o.mousedown(function(){m=b.caret()})},0)}function n(e){return('\n\n<!-- Begin {THING}: In order to preserve an editable {THING}, please\n     don\'t edit this section directly.\n     Click the "edit" link below the image in the preview instead. -->\n\n![{THING}]('+e+")\n\n<!-- End {THING} -->\n\n").replace(/{THING}/g,r)}var r=e.thingName,i=e.thingFinder,o=e.getIframeUrl,a=e.getDivContent,s=e.buttonTooltip,l=e.buttonImageUrl,c=e.onShow,u=e.onRemove||function(){},p=e.editLabel||"edit the above "+r,d=e.checkSupport;StackExchange.MarkdownEditor.creationCallbacks.add(t)}return{"init":e}}();