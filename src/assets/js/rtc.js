/**
 * @author Amir Sanni <amirsanni@gmail.com>
 * @date 6th January, 2020
 */
import h from './helpers.js';
import iceServer from '../json/ice-server.json' assert { type: 'json' };

window.addEventListener( 'load', () => {
    const room = h.getQString( location.href, 'room' );
    const username = sessionStorage.getItem( 'username' );
	document.querySelector('#video-username').children[0].title = username;

    if ( !room ) {
        document.querySelector( '#room-create' ).attributes.removeNamedItem( 'hidden' );
    }

    else if ( !username ) {
        document.querySelector( '#username-set' ).attributes.removeNamedItem( 'hidden' );
    }

    else {
		document.getElementById('navbar').style.visibility = 'unset';
        let commElem = document.getElementsByClassName( 'room-comm' );

        for ( let i = 0; i < commElem.length; i++ ) {
            commElem[i].attributes.removeNamedItem( 'hidden' );
        }

        var pc = [];
		var peerNamesById = {};

        let socket = io( '/stream' );

        var socketId = '';
        var randomNumber = `__${h.generateRandomString()}__${h.generateRandomString()}__`;
        var myStream = '';
        var screen = '';
        var recordedStream = [];
        var mediaRecorder = '';
		var screenSharingBool = false;

        //Get user video by default
        getAndSetUserStream();


        socket.on( 'connect', () => {
            //set socketId
            socketId = socket.io.engine.id;
            //document.getElementById('randomNumber').innerText = randomNumber;


            socket.emit( 'subscribe', {
                room: room,
                socketId: socketId
            } );


            socket.on( 'new user', ( data ) => {
                socket.emit( 'newUserStart', { to: data.socketId, sender: { id: socketId, name: username }});
                pc.push( data.socketId );
                init( true, data.socketId );
            } );

            socket.on( 'newUserStart', ( data ) => {
				const senderId = data.sender.id;
				peerNamesById[senderId] = data.sender.name;
                pc.push( senderId );
                init( false, senderId );
            } );


            socket.on( 'ice candidates', async ( data ) => {
                data.candidate ? await pc[data.sender].addIceCandidate( new RTCIceCandidate( data.candidate ) ) : '';
           	});


            socket.on( 'sdp', async ( data ) => {
                if ( data.description.type === 'offer' ) {
                    data.description ? await pc[data.sender].setRemoteDescription( new RTCSessionDescription( data.description ) ) : '';

                    h.getUserFullMedia().then( async ( stream ) => {
                        if ( !document.getElementById('local').srcObject ) {
							//console.log('on socket offer setLocalStream');
							h.setLocalStream( stream );
                        }

                        //save my stream
                        myStream = stream;

                        stream.getTracks().forEach( ( track ) => {
                            pc[data.sender].addTrack( track, stream );
                        } );

                        let answer = await pc[data.sender].createAnswer();
                        await pc[data.sender].setLocalDescription( answer );
                        socket.emit( 'sdp', { description: pc[data.sender].localDescription, to: data.sender, sender: { id: socketId, name: username }});
                    } ).catch( ( e ) => {
                        console.error( e );
                    } );
                }

                else if ( data.description.type === 'answer' ) {
					const senderId = data.sender.id;
					peerNamesById[senderId] = data.sender.name;
                    await pc[senderId].setRemoteDescription( new RTCSessionDescription( data.description ) );
                }
            } );


            socket.on( 'chat', ( data ) => {
                h.addChat( data, 'remote' );
            } );
        } );


        function getAndSetUserStream() {
            h.getUserFullMedia().then( ( stream ) => {
//console.log('getAndSetUserStream fn');
                //save my stream
                myStream = stream;

                h.setLocalStream( stream );
            } ).catch( ( e ) => {
                console.error( `stream error: ${ e }` );
            } );
        }


        function sendMsg( msg ) {
            let data = {
                room: room,
                msg: msg,
                sender: `${username} (${randomNumber})`
            };

            //emit chat message
            socket.emit( 'chat', data );

            //add localchat
            h.addChat( data, 'local' );
        }



        function init( createOffer, partnerName ) {
            pc[partnerName] = new RTCPeerConnection(iceServer);

            if ( screen && screen.getTracks().length ) {
//console.log('screen:', screen);
                screen.getTracks().forEach( ( track ) => {
                    pc[partnerName].addTrack( track, screen );//should trigger negotiationneeded event
                } );
				updateAudioTrack(); // if screen sharing when someone joins updateAudio based on mic state
            }

            else if ( myStream ) {
//console.log('myStream:', myStream);
                myStream.getTracks().forEach( ( track ) => {
                    pc[partnerName].addTrack( track, myStream );//should trigger negotiationneeded event
                } );
            }

            else {
//console.log('get my stream please');
                h.getUserFullMedia().then( ( stream ) => {
                    //save my stream
                    myStream = stream;

                    stream.getTracks().forEach( ( track ) => {
                        pc[partnerName].addTrack( track, stream );//should trigger negotiationneeded event
                    } );

	                h.setLocalStream(stream);
/*
					setTimeout(() => {
document.querySelector('#local').play() 
	.then(() => {
		console.log('Playback started');
	})
	.catch(error => {
		console.error('Playback failed:', error);
}); 
						console.log('set timeout for broadcast');
	                	broadcastNewTracks(myStream, 'video');
	                	broadcastNewTracks(myStream, 'audio');
						document.getElementById('local').play();
					}, 1000);
*/
                } ).catch( ( e ) => {
                    console.error( `stream error: ${ e }` );
                } );
            }


            //create offer
            if ( createOffer ) {
                pc[partnerName].onnegotiationneeded = async () => {
                    let offer = await pc[partnerName].createOffer();
                    await pc[partnerName].setLocalDescription( offer );
                    socket.emit( 'sdp', { description: pc[partnerName].localDescription, to: partnerName, sender: socketId } );
                };
            }



            //send ice candidate to partnerNames
            pc[partnerName].onicecandidate = ( { candidate } ) => {
                socket.emit( 'ice candidates', { candidate: candidate, to: partnerName, sender: socketId } );
            };



            //add
            pc[partnerName].ontrack = ( e ) => {
                let str = e.streams[0];
				const remoteVideo = document.getElementById(`${ partnerName }-video`);
                if (remoteVideo) {
                    remoteVideo.srcObject = str;
					remoteVideo.addEventListener('loadedmetadata', e => {
						e.target.play();
						h.resizeObserver.observe(e.target.parentNode);
					});
                }

                else {
                    //video elem
                    let newVid = document.createElement( 'video' );
                    newVid.id = `${ partnerName }-video`;
                    newVid.srcObject = str;
                    newVid.autoplay = true;
                    newVid.className = 'remote-video';
					newVid.setAttribute('playsinline', '');
					newVid.setAttribute('webkit-playsinline', '');
					//if (h.iosDevice) { newVid.classList.add('ios-video') };
					h.iosDeviceAddOns(newVid);

                    //video controls elements
                    let controlDiv = document.createElement( 'div' );
                    controlDiv.className = 'remote-video-controls';
                    controlDiv.innerHTML = `<i class="fa fa-microphone text-white pr-3 mute-remote-mic" title="Mute"></i>
                        <i class="fa fa-expand text-white expand-remote-video" title="Expand"></i>`;

					const nameDiv = document.createElement('div');
					nameDiv.id = 'video-username';
					nameDiv.appendChild(document.createElement('p'));
					nameDiv.childNodes[0].style.margin = '0';
					//nameDiv.childNodes[0].textContent = (Math.random() < 0.5) ? "Good looking" : "Need a brush up";
					nameDiv.childNodes[0].textContent = peerNamesById[partnerName];

					const handle = document.createElement('div');
					handle.classList.add('my-handle');
					handle.setAttribute('title', 'Drag and swap handle');

                    //create a new div for card
                    let cardDiv = document.createElement( 'div' );
                    cardDiv.className = 'card card-sm';
                    cardDiv.id = partnerName;
                    cardDiv.appendChild( newVid );
                    cardDiv.appendChild( controlDiv );
                    cardDiv.appendChild(nameDiv);
                    cardDiv.appendChild(handle);

                    //put div in main-section elem
                    document.getElementById( 'videos' ).appendChild( cardDiv );

                    //h.adjustVideoElemSize();
                }
            };



            pc[partnerName].onconnectionstatechange = ( d ) => {
                switch ( pc[partnerName].iceConnectionState ) {
                    case 'disconnected':
                    case 'failed':
                        h.closeVideo( partnerName );
                        break;

                    case 'closed':
                        h.closeVideo( partnerName );
                        break;
                }
            };



            pc[partnerName].onsignalingstatechange = ( d ) => {
                switch ( pc[partnerName].signalingState ) {
                    case 'closed':
                        console.log( "Signalling state is 'closed'" );
                        h.closeVideo( partnerName );
                        break;
                }
            };
        }



        function shareScreen() {
            h.shareScreen().then( ( stream ) => {
                h.toggleShareIcons( true );

                //disable the video toggle btns while sharing screen. This is to ensure clicking on the btn does not interfere with the screen sharing
                //It will be enabled was user stopped sharing screen
                h.toggleVideoBtnDisabled( true );

                //save my screen stream
                screen = stream;
				screenSharingBool = true;

                //share the new stream with all partners
                broadcastNewTracks( stream, 'video', false );
				updateAudioTrack();

                //When the stop sharing button shown by the browser is clicked
                screen.getVideoTracks()[0].addEventListener( 'ended', () => {
                    stopSharingScreen();
                } );
            } ).catch( ( e ) => {
                console.error( e );
            } );
        }

        function stopSharingScreen() {
            //enable video toggle btn
            h.toggleVideoBtnDisabled( false );
			screenSharingBool = false;

            return new Promise( ( res, rej ) => {
                screen.getTracks().length ? screen.getTracks().forEach( track => track.stop() ) : '';

                res();
            } ).then( () => {
                h.toggleShareIcons( false );
				updateAudioTrack();
                broadcastNewTracks( myStream, 'video' );
            } ).catch( ( e ) => {
                console.error( e );
            } );
        }

        function broadcastNewTracks( stream, type, mirrorMode = true ) {
			//console.log('broadcast set local stream');
            h.setLocalStream( stream, mirrorMode );

            let track = type == 'audio' ? stream.getAudioTracks()[0] : stream.getVideoTracks()[0];

			for (let i = 0; i < pc.length; i++) {
                const partnerName = pc[i];
				const recipientPeer = pc[partnerName];

				if (recipientPeer.getSenders) { 
    				const rtcSender = recipientPeer.getSenders().find(s => {
						// console.log("track.kind:", track.kind);
        				return s.track && s.track.kind === track.kind;
					});
					// console.log('recipientPeer:', recipientPeer);
					// console.log("rtcSender:", rtcSender);
       				rtcSender.replaceTrack( track );
				} else {
					return; 
				}
            }
        }


        function toggleRecordingIcons( isRecording ) {
            let e = document.getElementById( 'record' );

            if ( isRecording ) {
                e.setAttribute( 'title', 'Stop recording' );
                e.classList.replace('text-white', 'text-danger');
            }

            else {
                e.setAttribute( 'title', 'Record' );
                e.classList.replace('text-danger', 'text-white');
            }
        }


        function startRecording( stream ) {
            mediaRecorder = new MediaRecorder( stream, {
                mimeType: 'video/webm;codecs=vp9'
            } );

            mediaRecorder.start( 1000 );
            toggleRecordingIcons( true );

            mediaRecorder.ondataavailable = function ( e ) {
                recordedStream.push( e.data );
            };

            mediaRecorder.onstop = function () {
                toggleRecordingIcons( false );

                h.saveRecordedStream( recordedStream, username );

                setTimeout( () => {
                    recordedStream = [];
                }, 3000 );
            };

            mediaRecorder.onerror = function ( e ) {
                console.error( e );
            };
        }

        document.getElementById('chat-input-btn').addEventListener('click',(e) => {
            console.log("here: ",document.getElementById('chat-input').value)
            if (  document.getElementById('chat-input').value.trim()  ) {
                sendMsg( document.getElementById('chat-input').value );

                setTimeout( () => {
                    document.getElementById('chat-input').value = '';
                }, 50 );
            }
        });

        //Chat textarea
        document.getElementById( 'chat-input' ).addEventListener( 'keypress', ( e ) => {
            if ( e.which === 13 && ( e.target.value.trim() ) ) {
                e.preventDefault();

                sendMsg( e.target.value );

                setTimeout( () => {
                    e.target.value = '';
                }, 50 );
            }
        } );

	const toggleMyVideo = () => {
            let elem = document.getElementById('toggle-video');
            if ( myStream.getVideoTracks()[0].enabled ) {
                elem.classList.replace('fa-video', 'fa-video-slash');
                elem.setAttribute( 'title', 'Show Video' );
                myStream.getVideoTracks()[0].enabled = false;
            } else {
                elem.classList.replace('fa-video-slash', 'fa-video');
                elem.setAttribute( 'title', 'Hide Video' );
                myStream.getVideoTracks()[0].enabled = true;
            }
            broadcastNewTracks( myStream, 'video' );
	}

        document.addEventListener('keydown', e => { if (e.key === 'c') { toggleMyVideo() } });

        //When the video icon is clicked
        document.getElementById('toggle-video').addEventListener( 'click', ( e ) => {
        	e.preventDefault();
			toggleMyVideo();
        });

        //only on mobile devices
        const switchCamera = () => {
					navigator.mediaDevices.enumerateDevices()
						.then(devices => {
							const videoDevices = devices.filter(device => {
								const label = device.label.toLowerCase();
  							return device.kind === 'videoinput' && label.includes('back');
							});
							const rearCamera = { deviceId: videoDevices.at(-1).deviceId }; //creates constraint object with rear camera id
							const constraint = myStream.getVideoTracks()[0].getSettings().facingMode == "environment" ? "user" : rearCamera; //based on streams facingMode changes camera to front or rear by setting constraint
							h.getUserFullMedia(constraint).then(stream => {
								myStream = stream;
								const mirrorMode = myStream.getVideoTracks()[0].getSettings().facingMode == "user" ? true : false;
								broadcastNewTracks(myStream, 'video', mirrorMode);
							});
						})
						.catch(error => {
								console.error('Error enumerating devices:', error);
						});
        }
        document.getElementById('flip-video').addEventListener( 'click', ( e ) => {
        	e.preventDefault();
            switchCamera();
        });

	function updateAudioTrack() {
		const micAudioTrack = myStream.getAudioTracks()[0];

		const updateAttrs = (title) => {
			const elem = document.getElementById('toggle-mute');
			elem.classList.toggle('fa-microphone-alt', micAudioTrack.enabled);
			elem.classList.toggle('fa-microphone-alt-slash', !micAudioTrack.enabled);
			elem.setAttribute('title', title);
		};

		if (screenSharingBool) {
			// console.log('sharing screen audio: updateing mic icon and audio track');
			if (micAudioTrack.enabled) {
				updateAttrs('Share screen audio');
				broadcastNewTracks(myStream, 'audio');
				broadcastNewTracks(screen, 'video', false);
			} else {
				updateAttrs('Currently sharing screen audio');
				broadcastNewTracks(screen, 'audio', false);
			}
		} else {
			updateAttrs(micAudioTrack.enabled ? 'Mute' : 'Unmute');
			broadcastNewTracks(myStream, 'audio');
		}
	}

		const toggleAudio = () => {
			const micAudioTrack = myStream.getAudioTracks()[0];
			micAudioTrack.enabled = !micAudioTrack.enabled; // toggle mic audio
			updateAudioTrack();
		}

        document.addEventListener('keydown', e => { if (e.key === 'm') { toggleAudio() } });

        //When the mute icon is clicked
        document.getElementById('toggle-mute').addEventListener( 'click', ( e ) => {
            e.preventDefault();
			toggleAudio();
        });


        //When user clicks the 'Share screen' button
        document.getElementById( 'share-screen' ).addEventListener( 'click', ( e ) => {
            e.preventDefault();

            if ( screen && screen.getVideoTracks().length && screen.getVideoTracks()[0].readyState != 'ended' ) {
                stopSharingScreen();
            }

            else {
                shareScreen();
            }
        } );


        //When record button is clicked
        document.getElementById( 'record' ).addEventListener( 'click', ( e ) => {
            /**
             * Ask user what they want to record.
             * Get the stream based on selection and start recording
             */
            if ( !mediaRecorder || mediaRecorder.state == 'inactive' ) {
                h.toggleModal( 'recording-options-modal', true );
            }

            else if ( mediaRecorder.state == 'paused' ) {
                mediaRecorder.resume();
            }

            else if ( mediaRecorder.state == 'recording' ) {
                mediaRecorder.stop();
            }
        } );


        //When user choose to record screen
        document.getElementById( 'record-screen' ).addEventListener( 'click', () => {
            h.toggleModal( 'recording-options-modal', false );

            if ( screen && screen.getVideoTracks().length ) {
                startRecording( screen );
            }

            else {
                h.shareScreen().then( ( screenStream ) => {
                    startRecording( screenStream );
                } ).catch( () => { } );
            }
        } );


        //When user choose to record own video
        document.getElementById( 'record-video' ).addEventListener( 'click', () => {
            h.toggleModal( 'recording-options-modal', false );

            if ( myStream && myStream.getTracks().length ) {
                startRecording( myStream );
            }

            else {
                h.getUserFullMedia().then( ( videoStream ) => {
                    startRecording( videoStream );
                } ).catch( () => { } );
            }
        } );
    }
} );
