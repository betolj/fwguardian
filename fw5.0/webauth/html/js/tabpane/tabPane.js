/*
---
description: accessible tab pane 
 
license: MIT-style
 
authors:
- akaIDIOT
- Eva Loesch
- Philip Fieber
- Christian Merz
 
requires:
- core/1.2.4: Class
- core/1.2.4: Class.Extras
- core/1.2.4: Element
- core/1.2.4: Element.Event
- core/1.2.4: Selectors
- more/1.2.4: Element.Delegation
 
provides: accessible tab pane
 
version: 1.0
...
*/
(function() {

	var $ = document.id;

	this.TabPane = new Class(
			{

				Implements : [ Events, Options ],

				options : {
					tabSelector : '.tab',
					contentSelector : '.content',
					activeClass : 'active'
					// ########## START: EXTEND ##########
					// a flag, that shows if CTRL is pressed or not
					,
					ctrl : false,
					// a flag, that shows if ALT is pressed or not
					alt : false,
					// a flag, that shows if SHIFT is pressed or not
					shift : false,
					// prefixes used for IDs
					prefixTab : 'tab_',
					prefixPanel : 'panel_',
					// the current index of added sections
					index : 0,
					tabWithFocus : null,
					panelWithFocus : null,
					imageWithFocus : null,
					tabGroup : '.tabs'

				// ########## END: EXTEND ##########
				},

				container : null,
				showNow : false,
				// ########## START: EXTEND ##########
				tabs : null,
				contents : null,
				// ########## END: EXTEND ##########

				initialize : function(container, options) {
					this.setOptions(options);
					this.container = document.id(container);

					// save all available tabs in 'this.tabs':
					this.tabs = this.container
							.getChildren(this.options.tabGroup)[0]
							.getChildren(this.options.tabSelector);
					// save all available content areas in 'this.contents':
					this.contents = this.container
							.getChildren(this.options.contentSelector);
					// mark the first tab as active tab:
					this.tabs[0].addClass(this.options.activeClass);
					// hide all available contents:
					this.contents.setStyle('display', 'none');
					// show the content of the first tab:
					this.contents[0].setStyle('display', 'block');
					// add click event to the container to be able to select
					// tabs with
					// mouse clicks:
					this.container.addEvent('click:relay('
							+ this.options.tabSelector + ')', function(event,
							tab) {
						this.showTab(this.tabs.indexOf(tab), tab);
					}.bind(this));

					// ########## START: EXTEND ##########
					this.updateTabIndex();
					// add ARIA Roles
					// this.container.setProperty('role', 'application');
					// this.container.setProperty('role', 'tabpanel');
					this.container.getChildren('ul').setProperty('role',
							'tablist');
					//
					this.tabs
							.each(function(element, index){
								// add Key-Eventlistener
								// alert(index);
								
								// insert close image
								var img = new Element('img', {
									src: '/js/tabpane/img/close.gif',
									alt: 'Remove tab with space or enter'
								});

								if (element.getChildren()[0] != null) {
									element.addClass('delete');
									element.getChildren()[0].appendChild(img, 'top');
									// For Ipad accessibility we need to put the span put of the li
									clone = element.getChildren()[0].clone(true, true).inject(element, 'after');
									element.getChildren()[0].destroy();
								}
								
								// make closing image ("x") accessible
								//if (element.getChildren('span')[0] != null) {
								//Ipad...
								if (element.getNext() != null) {
									if (element.getNext().get('tag') == 'span') {
										//console.log(element.getChildren('span')[0]);
										//element.getChildren('span')[0].addEvent('keydown', function(event){
										//Ipad...
										element.getNext().addEvents({
										
											keydown: function(event){
											
												keyCode = this.getKeyCode(event);
												switch (keyCode) {
													// delete via enter or space
													case this.keys.KEY_ENTER:
													case this.keys.KEY_SPACE:
														var curInd = this.tabs.indexOf(this.container.getElement('.' +
														this.options.activeClass));
														this.closeTab(curInd);
														break;
													case this.keys.KEY_TAB:
														element.getNext().setProperty('tabindex', '-1');
														break;
													case this.keys.KEY_UP:
														if (event.control) {
								                    		event.stop();
															element.focus();
															this.options.ctrl = false;
															break;
															
														}
														else {
															if (this.options.tabWithFocus == null) {
																break;
															}
															
															if (anzTabs <= 1) {
																break;
															}
															
															if (previous == null) {
																this.activateTab(last, lastContent);
															}
															
															else {
																this.activateTab(previous, previousContent);
															}
								                            this.inactivateTab(thiz, thisContent);
								                            break;
														}
														break;
													default:
														break;
												}
											}
.bind(this)
										});
									}
									}
								element.addEvent('keydown', this.onKeyDown.bindWithEvent(this));
								element.addEvent('keyup', this.onKeyUp.bindWithEvent(this));
								element.addEvent('focus', function(event){
									this.options.tabWithFocus = element;
									this.options.panelWithFocus = null;
									this.updateTabIndex();
								
								}
.bind(this));
								element.addEvent('blur', function(){
									this.options.tabWithFocus = null;
								// alert('tab blur');
								}
.bind(this));
								// add ARIA Role
								element.setProperty('role', 'tab');
								// set ID
								element.setProperty('id', this.options.prefixTab +
								this.options.index);
								
								var content = this.contents[index];
								// set ID
								content.setProperty('id', this.options.prefixPanel +
								this.options.index);
								// add Key-Eventlistener
								content.addEvent('keydown', this.onKeyDown.bindWithEvent(this));
								content.addEvent('keyup', this.onKeyUp.bindWithEvent(this));
								content.addEvent('focus', function(){
									this.options.panelWithFocus = content;
								// alert('panel focus');
								}
.bind(this));
								content.addEvent('blur', function(){
								// alert('panel blur');
								// Do nothing
								}
.bind(this));
								// add ARIA Roles and Properties
								content.setProperty('role', 'tabpanel');
								content.setProperty('aria-labelledby', this.options.prefixTab +
								this.options.index);
								
								if (index == 0) {
									content.setProperty('aria-hidden', 'false');
									element.setProperty('aria-selected', 'true');
								// console.log('heyho');
								}
								else {
									content.setProperty('aria-hidden', 'true');
									element.setProperty('aria-selected', 'false');
								// console.log('heyho1');
								}
								
								// console.log('tab index: ' + index);
								
								// increment index
								this.options.index++;
								
							}.bind(this));
					// ########## END: EXTEND ##########
				},

				showTab : function(index, tab) {
					var content = this.contents[index];

					if (!tab) {
						tab = this.tabs[index];
					}

					if (content) {
						this.contents.each(function(el) {
							el.setStyle('display', 'none');
						});
						this.tabs.each(function(el) {
							el.removeClass(this.options.activeClass);
						}.bind(this));
						tab.addClass(this.options.activeClass);
						content.setStyle('display', 'block');
						this.fireEvent('change', index);
					}

					// ########## START: EXTEND ##########
					this.updateTabIndex();
					// ########## END: EXTEND ##########
				},

				closeTab : function(index) {
					var selected = this.tabs.indexOf(this.container
							.getElement('.' + this.options.activeClass)); // is
					// always
					// equals
					// to
					// index
					if(!this.getClosingImage(this.tabs[selected]))
						return;
					//IPAD...
					this.tabs[selected].getNext().destroy();
					this.tabs[selected].destroy();
					this.contents[selected].destroy();
					this.fireEvent('close', selected);
					cutt1 = this.tabs.slice(0, selected);
					cutt2 = this.tabs.slice(selected + 1, this.tabs.length);
					this.tabs = cutt1.concat(cutt2);

					cutc1 = this.contents.slice(0, selected);
					cutc2 = this.contents.slice(selected + 1,
							this.contents.length);
					this.contents = cutc1.concat(cutc2);

					// 'intelligently' selecting a tab is sadly not possible,
					// the tab
					// has already been switched before this method is called
					// ########## START: CHANGE ##########
					// comment this line, to prevent wrong tab to be focused
					// this.showTab(index == tabs.length - 1 ? selected - 1 :
					// selected);
					// ########## END: CHANGE ##########

					// ########## START: EXTEND ##########
					// allocate new IDs to each Tab and adjust the
					// aria-labelledby
					// attribute
					// in the corresponding panel

					// decrement index
					this.options.index--;
					if (this.tabs.length != 0) {
						if (selected == this.tabs.length) {
							selected--;
						}
						this.activateTab(this.tabs[selected],
								this.contents[selected]);
					}

					// ########## END: EXTEND ##########
				}
				// ########## START: EXTEND ##########
				// set tabindex to 0 for the active tab
				,
				updateTabIndex : function() {
					this.tabs.each(function(element, index) {
						if (element.hasClass(this.options.activeClass)) {
							element.setProperty('tabindex', 0);
							this.contents[index].setProperty('tabindex', 0);
							this.contents[index].setProperty('aria-hidden',
									'false');
							element.setProperty('aria-selected', 'true');
							// if no closing sign is declared do nothing
							if (this.getClosingImage(element))
								this.getClosingImage(element).setProperty('tabindex', '0');
						} else {
							element.setProperty('tabindex', -1);
							this.contents[index].setProperty('tabindex', -1);
							this.contents[index].setProperty('aria-hidden',
									'true');
							element.setProperty('aria-selected', 'false');
							// if no closing sign is declared do nothing
							if (this.getClosingImage(element))
								this.getClosingImage(element).setProperty('tabindex', '-1');
						}

					}.bind(this));

				},
				// Keyevents- and listeners
				keys : {
					KEY_TAB : 9,
					KEY_ENTER : 13,
					KEY_SHIFT : 16,
					KEY_CTRL : 17,
					KEY_ALT : 18,
					KEY_SPACE : 32,
					KEY_PAGEUP : 33,
					KEY_PAGEDOWN : 34,
					KEY_END : 35,
					KEY_HOME : 36,
					KEY_LEFT : 37,
					KEY_UP : 38,
					KEY_RIGHT : 39,
					KEY_DOWN : 40,
					KEY_DEL : 46
				},

				// get the keycode for the thrown event
				getKeyCode : function(event) {
					var keyCode;
					// works in IE 8 and FF 3
					if (window.event) {
						keyCode = window.event.keyCode;
					} else {
						keyCode = event.code;
					}
					return keyCode;
				},

				// set all attributes for activating a Tab
				activateTab : function(tab, content) {
					if(tab.getProperty('tabindex') == 0)
						return
					
					setTimeout(function() {
						tab.focus();
					}, 0);
					tab.setProperty('tabindex', 0);
					content.setProperty('tabindex', 0);
					tab.addClass(this.options.activeClass);
					content.setStyle('display', 'block');
					content.setProperty('aria-hidden', 'false');
					tab.setProperty('aria-selected', 'true');
					// if no closing sign is declared do nothing
					if (this.getClosingImage(tab))
						this.getClosingImage(tab).setProperty('tabindex', '0');
					// console.log(this.getClosingImage(tab));
					// console.log('activate');
				},

				// set all attributes for inactivating a Tab
				inactivateTab : function(tab, content) {
					if(!tab || tab.getProperty('tabindex') == -1)
						return
					
					tab.setProperty('tabindex', -1);
					tab.removeClass(this.options.activeClass);
					content.setStyle('display', 'none');
					content.setProperty('aria-hidden', 'true');
					tab.setProperty('aria-selected', 'false');
					content.setProperty('tabindex', -1);
					// if no closing sign is declared do nothing
					if (this.getClosingImage(tab))
						this.getClosingImage(tab).setProperty('tabindex', '-1');
					// console.log('inactivate');

				},

				// returns the span class surrounding the closing image of the
				// tab
				getClosingImage : function(tab) {
					if (tab.getNext() != null) {
						if (tab.getNext().get('tag') == 'span') {
							return tab.getNext().getFirst();
							}
						}
					
					return null;
				},

				onFocusElement : function(event) {
					alert();
					this.options.tabWithFocus = element;
					this.options.panelWithFocus = null;
					// console.log('tabWithFocus!!!!!!!');
					// alert('focus element: ');
				},

				onBlurElement : function() {
					// alert('blur element');
					this.options.tabWithFocus = null;
					// console.log('---->tabWithFocus is null');
				},

				onFocusContent : function() {
					// alert('focus content');
				},

				onBlurContent : function() {
					// alert('blur content');
				},

				onKeyDown : function(event) {

					var keyCode = this.getKeyCode(event);

					var currentIndex = this.tabs.indexOf(this.container
							.getElement('.' + this.options.activeClass));
					var anzTabs = this.tabs.length;

					var first = this.tabs[0];
					var last = this.tabs[anzTabs - 1];
					var next = this.tabs[currentIndex + 1];
					var previous = this.tabs[currentIndex - 1];
					var thiz = this.tabs[currentIndex];

					var firstContent = this.contents[0];
					var lastContent = this.contents[anzTabs - 1];
					var nextContent = this.contents[currentIndex + 1];
					var previousContent = this.contents[currentIndex - 1];
					var thisContent = this.contents[currentIndex];
					switch (keyCode) {

					case this.keys.KEY_LEFT:

                        event.stop();
						if (this.options.tabWithFocus == null) {
							// alert('key left focus null');
							break;
						}

						if (this.options.ctrl) {
							// alert('key left ctrl');
							break;
						}

						if (anzTabs <= 1) {
							// alert('key left <=1 Tab');
							break;
						}

						if (previous == null) {
							// alert('key left previous null');
							this.activateTab(last, lastContent);
						} else {
							// alert('key left else');
							this.activateTab(previous, previousContent);
						}

						this.inactivateTab(thiz, thisContent);

						break;

					case this.keys.KEY_UP:
                        event.stop();
						if (event.control) {
                    		event.stop();
							if (this.options.panelWithFocus == null) {
								// console.log('panelWIthFocus == null');
								break;
							}
							currentIndex = parseInt(this.options.panelWithFocus.getAttribute('aria-labelledby').replace(this.options.prefixTab, ''));
							this.tabs[currentIndex].focus();
							this.options.ctrl = false;
							break;
							
						}
						else {
							if (this.options.tabWithFocus == null) {
								break;
							}
							
							if (anzTabs <= 1) {
								break;
							}
							
							if (previous == null) {
								this.activateTab(last, lastContent);
							}
							
							else {
								this.activateTab(previous, previousContent);
							}
                            this.inactivateTab(thiz, thisContent);
                            break;
						}


					case this.keys.KEY_DOWN:

					case this.keys.KEY_RIGHT:

						// console.log('hi');

						if (this.options.tabWithFocus == null) {
							// console.log('tabWithFocus is null');
							break;
						}

						if (this.options.ctrl) {
							// console.log('ctrl is pressed');
							break;
						}

						if (anzTabs <= 1) {
							// console.log('only one tab');
							break;
						}

                        event.stop();
						// console.log('should work');
						if (next == null) {
							this.activateTab(first, firstContent);
						} else {
							this.activateTab(next, nextContent);
						}

						this.inactivateTab(thiz, thisContent);
						break;

					case this.keys.KEY_PAGEUP:

						if (anzTabs <= 1) {
							break;
						}

						if (this.options.ctrl) {
							if (this.options.panelWithFocus == null) {

								break;
							}

							currentIndex = parseInt(this.options.panelWithFocus
									.getAttribute('aria-labelledby').replace(
											this.options.prefixTab, ''));

							if ((currentIndex - 1) < 0) {
								this.activateTab(this.tabs[anzTabs - 1],
										this.contents[anzTabs - 1]);
							}

							else {
								this.activateTab(this.tabs[currentIndex - 1],
										this.contents[currentIndex - 1]);
							}

							this.inactivateTab(this.tabs[currentIndex],
									this.contents[currentIndex]);

							this.options.ctrl = false;

						}
						break;

					case this.keys.KEY_PAGEDOWN:

						if (anzTabs <= 1) {
							break;
						}

						if (this.options.ctrl) {

							if (this.options.panelWithFocus == null) {
								break;
							}

							currentIndex = parseInt(this.options.panelWithFocus
									.getAttribute('aria-labelledby').replace(
											this.options.prefixTab, ''));

							if ((currentIndex + 1) > (anzTabs - 1)) {
								this
										.activateTab(this.tabs[0],
												this.contents[0]);
							}

							else {
								this.activateTab(this.tabs[currentIndex + 1],
										this.contents[currentIndex + 1]);
							}

							this.inactivateTab(this.tabs[currentIndex],
									this.contents[currentIndex]);

							this.options.ctrl = false;

						}
						break;

					case this.keys.KEY_DEL:
						if (this.options.alt) {

							if (this.options.tabWithFocus == null) {
								break;
							}

							this.closeTab(currentIndex);
						}

						break;

					case this.keys.KEY_CTRL:
						this.options.ctrl = true;
						// console.log('this.options.ctrl = true;');
						break;

					case this.keys.KEY_ALT:
						this.options.alt = true;
						break;

					case this.keys.KEY_SHIFT:
						this.options.shift = true;
						break;

					case this.keys.KEY_HOME:

						if (this.options.ctrl)
							break;

						if (this.options.tabWithFocus == null) {
							break;
						}

						if (anzTabs <= 1) {
							break;
						}
						event.stop();
						if(first == thiz)
							break
						this.activateTab(first, firstContent);
						this.inactivateTab(thiz, thisContent);

						break;

					case this.keys.KEY_END:
						if (this.options.ctrl) {
							break;
						}

						if (this.options.tabWithFocus == null) {
							break;
						}

						if (anzTabs <= 1) {
							break;
						}
						event.stop();
						if(last == thiz)
							break
						this.activateTab(last, lastContent);
						this.inactivateTab(thiz, thisContent);

						break;

					}
				},

				onKeyUp : function(event) {
					var keyCode = this.getKeyCode(event);

					switch (keyCode) {
					case this.keys.KEY_CTRL:
						this.options.ctrl = false;
						break;
					case this.keys.KEY_ALT:
						this.options.alt = false;
						break;
					}
				}
			// ########## END: EXTEND ##########

			});

})();
