!function a(b,c,d){function e(g,h){if(!c[g]){if(!b[g]){var i="function"==typeof require&&require;if(!h&&i)return i(g,!0);if(f)return f(g,!0);var j=new Error("Cannot find module '"+g+"'");throw j.code="MODULE_NOT_FOUND",j}var k=c[g]={exports:{}};b[g][0].call(k.exports,function(a){var c=b[g][1][a];return e(c||a)},k,k.exports,a,b,c,d)}return c[g].exports}for(var f="function"==typeof require&&require,g=0;g<d.length;g++)e(d[g]);return e}({1:[function(a,b,c){"use strict";function d(a){var b=jQuery("#gsc_count_"+a),c=parseInt(b.text(),10)-1;c<0&&(c=0),b.text(c)}function e(a,b,c,e){jQuery.post(ajaxurl,{action:"wpseo_mark_fixed_crawl_issue",ajax_nonce:a,platform:b,category:c,url:e},function(a){"true"===a&&(d(jQuery("#field_category").val()),jQuery('span:contains("'+e+'")').closest("tr").remove())})}function f(a){e(jQuery(".wpseo-gsc-ajax-security").val(),jQuery("#field_platform").val(),jQuery("#field_category").val(),a)}jQuery(function(){var a;jQuery("#gsc_auth_code").click(function(){var a=jQuery("#gsc_auth_url").val(),b=screen.width/2-300,c=screen.height/2-250;return window.open(a,"wpseogscauthcode","toolbar=no, location=no, directories=no, status=no, menubar=no, scrollbars=yes, resizable=no, copyhistory=no, width=600, height=500, top="+c+", left="+b)}),jQuery(".wpseo-open-gsc-redirect-modal").click(function(b){var c,d,e,f,g=jQuery(this).text();b.preventDefault(),b.stopPropagation(),a=jQuery(this),tb_click.call(this),c=jQuery("#TB_window"),d=jQuery("#TB_ajaxWindowTitle"),e=jQuery("#TB_closeWindowButton"),f=jQuery(".wpseo-redirect-close",c),d.text(g),c.attr({role:"dialog","aria-labelledby":"TB_ajaxWindowTitle","aria-describedby":"TB_ajaxContent"}).on("keydown",function(a){var b;9===a.which&&(b=a.target.id,jQuery(a.target).hasClass("wpseo-redirect-close")&&!a.shiftKey?(e.focus(),a.preventDefault()):"TB_closeWindowButton"===b&&a.shiftKey&&(f.focus(),a.preventDefault()))})}),jQuery(document.body).on("click",".wpseo-redirect-close",function(){jQuery(this).closest("#TB_window").find("#TB_closeWindowButton").trigger("click")}).on("thickbox:removed",function(){a.focus()})}),window.wpseo_update_category_count=d,window.wpseo_mark_as_fixed=f,window.wpseo_send_mark_as_fixed=e},{}]},{},[1]);