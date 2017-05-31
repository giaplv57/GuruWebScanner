// JavaScript Document
(function() {
	tinymce.create('tinymce.plugins.kkStarRatings', {
		init : function(ed, url) {

			// Register button and click event
			ed.addButton('kkstarratings', {
				title : 'kk Star Ratings',
				cmd : 'mceKKStarRatings',
				image: url + '/icon.png',
				onClick : function(){
					ed.execCommand('mceReplaceContent', false, "[kkstarratings]");
				}});
		},

		getInfo : function() {
			return {
				longname : 'kk Star Ratings',
				author : 'Kamal Khan',
				authorurl : 'http://bhittani.com',
				infourl : 'http://bhittani.com',
				version : tinymce.majorVersion + "." + tinymce.minorVersion
			};
		}
	});

	// Register plugin
	tinymce.PluginManager.add('kkstarratings', tinymce.plugins.kkStarRatings);

})();
