import helpers from './helpers.js';

window.addEventListener( 'load', () => {
	//if (helpers.iosDevice) { document.getElementById('local').classList.add('ios-video') };
	helpers.iosDeviceAddOns(document.querySelector('#local'));

	Sortable.create(videos, {
		animation: 100,
		handle: ".my-handle",
	});

	if (/Mobi|Android|iPhone|iPad|iPod/i.test(navigator.userAgent) || (navigator.maxTouchPoints > 2 && /MacIntel/.test(navigator.platform))) {
		document.getElementById('share-screen').style.display = "none";
		document.getElementById('record').style.display = "none";
		document.getElementById('flip-video').style.display = "";
	}

	document.getElementById('local').addEventListener('loadedmetadata', e => { 
		e.target.play() 
  			//.then(() => {
    		//	console.log('Playback started');
  			//})
  			.catch(error => {
    			console.error('Playback failed:', error);
		});
		helpers.resizeObserver.observe(e.target.parentNode);
	});
	//document.getElementById('local').addEventListener('loadedmetadata', e => { helpers.resizeObserver.observe(e.target.parentNode) });
	window.addEventListener('resize', helpers.adjustVideoElemSize);

    //When the chat icon is clicked
    document.querySelector( '#toggle-chat-pane' ).addEventListener( 'click', ( e ) => {
        let chatElem = document.querySelector( '#chat-pane' );
        let mainSecElem = document.querySelector( '#main-section' );

        if ( chatElem.classList.contains( 'chat-opened' ) ) {
            chatElem.setAttribute( 'hidden', true );
            mainSecElem.classList.remove( 'col-md-9' );
            mainSecElem.classList.add( 'col-md-12' );
            chatElem.classList.remove( 'chat-opened' );
        }

        else {
			chatElem.attributes.removeNamedItem('hidden');
            mainSecElem.classList.remove( 'col-md-12' );
            mainSecElem.classList.add( 'col-md-9' );
            chatElem.classList.add( 'chat-opened' );
        }

        //remove the 'New' badge on chat icon (if any) once chat is opened.
        setTimeout( () => {
            if ( document.querySelector( '#chat-pane' ).classList.contains( 'chat-opened' ) ) {
                helpers.toggleChatNotificationBadge();
            }
        }, 300 );
    } );

/*
    //When the video frame is clicked. This will enable picture-in-picture
    document.getElementById( 'local' ).addEventListener( 'click', () => {
        if ( !document.pictureInPictureElement ) {
            document.getElementById( 'local' ).requestPictureInPicture()
                .catch( error => {
                    // Video failed to enter Picture-in-Picture mode.
                    console.error( error );
                } );
        }

        else {
            document.exitPictureInPicture()
                .catch( error => {
                    // Video failed to leave Picture-in-Picture mode.
                    console.error( error );
                } );
        }
    } );
*/

	const createRoom = e => {
        const roomName = document.querySelector( '#room-name' ).value;
        const yourName = document.querySelector( '#your-name' ).value;
		const roomCreated = document.querySelector('#room-created');
		const roomLink = (roomName && yourName) ? `${location.origin}?room=${roomName.trim().replace(' ','_')}` : (roomCreated.innerHTML ? roomCreated.children[0].href : '');

		if (!roomLink) {
        	document.querySelector('#err-msg').innerText = "All fields are required";
		} else {
			if (yourName) { sessionStorage.setItem( 'username', yourName ); }
            document.querySelector('#err-msg').innerText = "";
			document.querySelector( '#room-name' ).value = '';
            document.querySelector( '#your-name' ).value = '';
			if (e.key && e.key === 'Enter') {
				window.location.assign(roomLink);
			} else {
            	roomCreated.innerHTML = `Room successfully created. Click <a href='${ roomLink }'>here</a> to enter room.\nShare the room link with your partners.`;
				roomCreated.style.fontSize = '1.2rem';
			}
		}
	}

    //When the 'Create room" is button is clicked
    document.getElementById('create-room').addEventListener('click', e => { 
        e.preventDefault();
		createRoom(e);
	});

	const enterRoom = e => {
        const name = document.querySelector('#username').value;

        if (name) {
            //remove error message, if any
            document.querySelector('#err-msg-username').innerText = "";

            //save the user's name in sessionStorage
            sessionStorage.setItem('username', name);

            //reload room
            location.reload();
        } else {
            document.querySelector('#err-msg-username').innerText = "Please input your name";
        }
	}
    //When the 'Enter room' button is clicked.
    document.getElementById('enter-room').addEventListener('click', e => { 
        e.preventDefault();
		enterRoom(e);
    });

	//Enable enter key on homepage and your name page
    if (window.location.href === 'https://call.talkofchrist.org/') {
		document.addEventListener('keydown', e => { if (e.key === 'Enter') { createRoom(e) } }); 
	} else if (!sessionStorage[username]) {
    	document.addEventListener('keydown', e => { if (e.key === 'Enter') { enterRoom(e) } });
	}

    document.addEventListener( 'click', ( e ) => {
        if ( e.target && e.target.classList.contains( 'expand-remote-video' ) ) {
            helpers.maximiseStream( e );
        }

        else if ( e.target && e.target.classList.contains( 'mute-remote-mic' ) ) {
            helpers.singleStreamToggleMute( e );
        }
    } );


    document.getElementById( 'closeModal' ).addEventListener( 'click', () => {
        helpers.toggleModal( 'recording-options-modal', false );
    } );
} );
