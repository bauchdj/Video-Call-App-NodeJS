function adjustVideoElemSize() {
    const videoContainer = document.getElementById( 'video-container' );
    //const navbarOffsetHeight = document.querySelector('.navbar').offsetHeight;
    //videoContainer.style.bottom = `${navbarOffsetHeight}px`;

    const videoCardEls = document.querySelectorAll('#videos .card');
    const totalVideos = videoCardEls.length;
	const screenWidthLimit = 800;

    function calcNewWidth(totalVideos) {
        if (totalVideos == 1) return '100%';
        if (totalVideos <= 4) return '50%';
        if (totalVideos <= 6) return '33.3%';
        if (totalVideos <= 8) return '25%';
        if (totalVideos <= 15) return '20%';
        if (totalVideos <= 18) return '16%';
        if (totalVideos <= 23) return '15%';
        if (totalVideos <= 32) return '12%';
        return '50%';
    }

    for ( let i = 0; i < totalVideos; i++ ) {
        if (window.innerWidth < screenWidthLimit) {
            videoCardEls[i].style.width = "100%";
        } else {
            videoCardEls[i].style.width = calcNewWidth(totalVideos);
        }
    }
        
    function scaleVideoContainer() {
		const setVideoContainerWidth = width => videoContainer.style.width = width;
        if ( window.innerWidth < screenWidthLimit ) {
			videoContainer.style.overflow = "auto";
            setVideoContainerWidth('100%');
        } else {
			videoContainer.style.overflow = "unset";
      	    setVideoContainerWidth('100%');
           	const desiredHeight = videoContainer.offsetHeight;
           	const scrollHeight = videoContainer.scrollHeight;
           	const width = ( ( desiredHeight / scrollHeight ) * 100 );
           	setVideoContainerWidth(`${width}%`);
        }
    }

    scaleVideoContainer();
    //setTimeout(() => scaleVideoContainer(), 1000);
}

export default {
	adjustVideoElemSize: adjustVideoElemSize,

	resizeObserver: new ResizeObserver(entries => adjustVideoElemSize()),

	iosDevice: (navigator.userAgent.match(/(iPod|iPhone|iPad)/)),

	iosDeviceAddOns: e => {
		if (navigator.userAgent.match(/(iPod|iPhone|iPad)/)) {
			console.log('ios device');
			e.addEventListener("pause", () => {
  				e.play();
			});
  			const match = navigator.userAgent.match(/OS (\d+)_(\d+)_?(\d+)?/);
  			const version = match ? Number(match[1]) : null;
			if (version !== null && version < 16) {
				console.log('ios', version);
				//e.classList.add('ios-video');
			}
		}
	},

    generateRandomString() {
        const crypto = window.crypto || window.msCrypto;
        let array = new Uint32Array(1);
        
        return crypto.getRandomValues(array);
    },


    closeVideo( elemId ) {
        if ( document.getElementById( elemId ) ) {
            document.getElementById( elemId ).remove();
            this.adjustVideoElemSize();
        }
    },


    pageHasFocus() {
        return !( document.hidden || document.onfocusout || window.onpagehide || window.onblur );
    },


    getQString( url = '', keyToReturn = '' ) {
        url = url ? url : location.href;
        let queryStrings = decodeURIComponent( url ).split( '#', 2 )[0].split( '?', 2 )[1];

        if ( queryStrings ) {
            let splittedQStrings = queryStrings.split( '&' );

            if ( splittedQStrings.length ) {
                let queryStringObj = {};

                splittedQStrings.forEach( function ( keyValuePair ) {
                    let keyValue = keyValuePair.split( '=', 2 );

                    if ( keyValue.length ) {
                        queryStringObj[keyValue[0]] = keyValue[1];
                    }
                } );

                return keyToReturn ? ( queryStringObj[keyToReturn] ? queryStringObj[keyToReturn] : null ) : queryStringObj;
            }

            return null;
        }

        return null;
    },


    userMediaAvailable() {
        return !!( navigator.getUserMedia || navigator.webkitGetUserMedia || navigator.mozGetUserMedia || navigator.msGetUserMedia );
    },


    getUserFullMedia(constraint = true) {
    	if ( this.userMediaAvailable() ) {
            return navigator.mediaDevices.getUserMedia( {
                video: constraint,
                audio: {
                    echoCancellation: true,
                    noiseSuppression: true
                }
            } );
        }

        else {
            throw new Error( 'User media not available' );
        }
    },


    getUserAudio() {
        if ( this.userMediaAvailable() ) {
            return navigator.mediaDevices.getUserMedia( {
                audio: {
                    echoCancellation: true,
                    noiseSuppression: true
                }
            } );
        }

        else {
            throw new Error( 'User media not available' );
        }
    },



    shareScreen() {
        if ( this.userMediaAvailable() ) {
            return navigator.mediaDevices.getDisplayMedia( {
                video: {
                    cursor: "always"
                },
                audio:  {
                    echoCancellation: true,
                    noiseSuppression: true,
                    sampleRate: 44100
                }
            } );
        }

        else {
            throw new Error( 'User media not available' );
        }
    },


    getIceServer() {
        return {
            iceServers: [
                {
                    urls: "stun:stun.l.google.com:19302"
                },
                {
                    username: "gorst",
                    credential: "turn4ezmdm",
                    urls: "turn:3.218.145.16:13478?transport=udp",
                }
            ]
        };
    },


    addChat( data, senderType ) {
        let chatMsgDiv = document.querySelector( '#chat-messages' );
        let contentAlign = 'justify-content-end';
        let senderName = 'You';
        let msgBg = 'bg-white';

        if ( senderType === 'remote' ) {
            contentAlign = 'justify-content-start';
            senderName = data.sender.split('(')[0].split(/ $/)[0];
            msgBg = '';

            this.toggleChatNotificationBadge();
        }

        let infoDiv = document.createElement( 'div' );
        infoDiv.className = 'sender-info';
        infoDiv.innerText = `${ senderName } - ${ moment().format( 'Do MMMM, YYYY h:mm a' ) }`;

        let colDiv = document.createElement( 'div' );
        colDiv.className = `col-10 card chat-card msg ${ msgBg }`;
        colDiv.innerHTML = xssFilters.inHTMLData( data.msg ).autoLink( { target: "_blank", rel: "nofollow"});
        colDiv.style.padding = '3px';

        let rowDiv = document.createElement( 'div' );
        rowDiv.className = `row ${ contentAlign } mb-2`;
		    rowDiv.style.marginLeft = 0;
		    rowDiv.style.marginRight = 0;

        colDiv.appendChild( infoDiv );
        rowDiv.appendChild( colDiv );

        chatMsgDiv.appendChild( rowDiv );

        /**
         * Move focus to the newly added message but only if:
         * 1. Page has focus
         * 2. User has not moved scrollbar upward. This is to prevent moving the scroll position if user is reading previous messages.
         */
        if ( this.pageHasFocus ) {
            rowDiv.scrollIntoView();
        }
    },


    toggleChatNotificationBadge() {
        if ( document.querySelector( '#chat-pane' ).classList.contains( 'chat-opened' ) ) {
            document.querySelector( '#new-chat-notification' ).setAttribute( 'hidden', true );
        }

        else {
            document.querySelector( '#new-chat-notification' ).removeAttribute( 'hidden' );
        }
    },


    toggleShareIcons( share ) {
        let shareIconElem = document.querySelector( '#share-screen' );

		const setTitle = title => { shareIconElem.setAttribute('title', title) };
        if ( share ) {
            setTitle('Stop sharing screen');
            shareIconElem.classList.replace('text-white', 'text-primary');
        }

        else {
            setTitle('Share screen');
            shareIconElem.classList.replace('text-primary', 'text-white');
        }
    },


    toggleVideoBtnDisabled( disabled ) {
        document.getElementById( 'toggle-video' ).disabled = disabled;
    },


    maximiseStream( e ) {
        let elem = e.target.parentElement.previousElementSibling;

        //elem.webkitRequestFullscreen() || elem.mozRequestFullScreen() || elem.msRequestFullscreen() || elem.requestFullscreen();
  if (elem.requestFullscreen) {
    elem.requestFullscreen();
  } else if (elem.mozRequestFullScreen) {
    elem.mozRequestFullScreen();
  } else if (this.iosDevice) {
	console.log('Safari iOS');
    elem.webkitEnterFullScreen();
  } else if (elem.webkitRequestFullscreen) {
      elem.webkitRequestFullScreen();
  } else if (elem.msRequestFullscreen) {
    elem.msRequestFullscreen();
  } else {
    console.log('Fullscreen not working :(');
  }
    },


    singleStreamToggleMute( e ) {
        if ( e.target.classList.contains( 'fa-microphone' ) ) {
            e.target.parentElement.previousElementSibling.muted = true;
            e.target.classList.replace('fa-microphone', 'fa-microphone-slash' );
        }

        else {
            e.target.parentElement.previousElementSibling.muted = false;
            e.target.classList.replace('fa-microphone-slash', 'fa-microphone' );
        }
    },


    saveRecordedStream( stream, user ) {
        let blob = new Blob( stream, { type: 'video/webm' } );

        let file = new File( [blob], `${ user }-${ moment().unix() }-record.webm` );

        saveAs( file );
    },


    toggleModal( id, show ) {
        let el = document.getElementById( id );

        if ( show ) {
            el.style.display = 'block';
            el.removeAttribute( 'aria-hidden' );
        }

        else {
            el.style.display = 'none';
            el.setAttribute( 'aria-hidden', true );
        }
    },



    setLocalStream( stream, mirrorMode = true ) {
        const myVideoEl = document.getElementById( 'local' );
		myVideoEl.srcObject = stream;
        mirrorMode ? myVideoEl.classList.add( 'mirror-mode' ) : myVideoEl.classList.remove( 'mirror-mode' );
    },
};
