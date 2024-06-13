import classNames from 'clsx';
import {
	MouseEvent,
	ReactNode,
	createContext,
	forwardRef,
	useContext,
	useEffect,
	useRef,
	useState,
} from 'react';
import { Button } from '../button.js';
import { Icon } from '../icon.js';
import { Select, SelectContent, SelectItem, SelectTrigger } from '../select.js';
import { Slot } from '@radix-ui/react-slot';
import { withClassName } from '../../hooks.js';

const CameraContext = createContext<{
	triggerCapture: () => void;
	selectedDeviceId: string | undefined;
	selectDeviceId: (id: string) => void;
	devices: MediaDeviceInfo[];
}>({
	triggerCapture: () => {},
	selectedDeviceId: 'default',
	selectDeviceId: () => {},
	devices: [],
});

export interface CameraRootProps {
	className?: string;
	onCapture?: (data: File) => void;
	children?: ReactNode;
	format?: 'image/png' | 'image/jpeg';
	facingMode?: 'user' | 'environment';
}

export const CameraRoot = forwardRef<HTMLDivElement, CameraRootProps>(
	function Camera(
		{
			className,
			onCapture,
			children,
			facingMode,
			format = 'image/png',
			...rest
		},
		ref,
	) {
		const videoRef = useRef<HTMLVideoElement>(null);

		const [devices, setDevices] = useState<MediaDeviceInfo[]>([]);
		const [stream, setStream] = useState<MediaStream | undefined>();

		useEffect(() => {
			navigator.mediaDevices?.enumerateDevices().then((devices): void => {
				setDevices(devices.filter((device) => device.kind === 'videoinput'));
			});
		}, [!!stream]);

		const [selectedDeviceId, setSelectedDeviceId] = useState<
			string | undefined
		>();

		useEffect(() => {
			const init = () => {
				navigator.mediaDevices
					?.getUserMedia({
						video: {
							deviceId: selectedDeviceId,
							facingMode,
						},
					})
					.then((s) => {
						setStream(s);
					});
			};
			init();

			// reconnect if browser was backgrounded
			const reconnect = () => {
				if (stream?.active || document.visibilityState !== 'visible') {
					return;
				}
				init();
			};
			document.addEventListener('visibilitychange', reconnect);
		}, [selectedDeviceId, facingMode]);

		useEffect(() => {
			return () => {
				stream?.getTracks().forEach((track) => track.stop());
			};
		}, [stream]);

		useEffect(() => {
			const video = videoRef.current;
			if (video && stream) {
				video.srcObject = stream;
				return () => {
					video.srcObject = null;
				};
			}
		}, [stream]);

		const [capture, setCapture] = useState<ImageCapture>();

		useEffect(() => {
			if (typeof window !== 'undefined' && 'ImageCapture' in window) {
				const videoTrack = stream?.getVideoTracks()[0];
				if (videoTrack) {
					const capturer = new ImageCapture(videoTrack);
					setCapture(capturer);
					capturer.getPhotoCapabilities().then((capabilities) => {
						console.log('ImageCapture capabilities:', capabilities);
					});
				}
			}
		}, [stream]);

		const triggerCapture = () => {
			if (capture) {
				capture.takePhoto().then((blob) => {
					const file = new File([blob], `image.${format.split('/')[1]}`, {
						type: format,
					});
					onCapture?.(file);
				});
			} else {
				// ImageCapture not supported, fallback to
				// canvas capture
				const video = videoRef.current;
				if (video) {
					const canvas = document.createElement('canvas');
					canvas.width = video.videoWidth;
					canvas.height = video.videoHeight;
					canvas.getContext('2d')?.drawImage(video, 0, 0);
					const data = canvas.toDataURL(format);
					const file = dataURItoFile(data);
					onCapture?.(file);
				}
			}
		};

		return (
			<CameraContext.Provider
				value={{
					devices,
					triggerCapture,
					selectedDeviceId,
					selectDeviceId: setSelectedDeviceId,
				}}
			>
				<div
					ref={ref}
					className={classNames(
						'layer-components:([font-family:inherit] text-white bg-black rounded-lg overflow-hidden min-w-4 min-h-4 relative)',
						className,
					)}
					{...rest}
				>
					<video
						ref={videoRef}
						className="w-full h-full object-cover"
						autoPlay
						muted
						playsInline
					></video>
					{children}
				</div>
			</CameraContext.Provider>
		);
	},
);

export interface CameraShutterButtonProps {
	className?: string;
	asChild?: boolean;
	onClick?: (ev: MouseEvent<HTMLButtonElement>) => void;
}

export const CameraShutterButton = forwardRef<
	HTMLButtonElement,
	CameraShutterButtonProps
>(function CameraShutterButton({ asChild, onClick, ...rest }, ref) {
	const Comp = asChild ? Slot : StyledShutterButton;
	const { triggerCapture } = useContext(CameraContext);

	return (
		<Comp
			ref={ref}
			aria-label={asChild ? undefined : 'Capture photo'}
			onClick={(ev) => {
				triggerCapture();
				onClick?.(ev);
			}}
			{...rest}
		/>
	);
});

const StyledShutterButton = withClassName(
	'button',
	'absolute bottom-3 left-1/2 -translate-x-1/2 w-16 h-16 bg-white rounded-full cursor-pointer border-2 border-black border-solid ring-2 ring-white opacity-80',
	'hover:bg-gray-1 hover:opacity-100',
	'focus-visible:bg-gray-2',
	'focus:ring-primary focus:outline-none focus:opacity-100',
	'sm:w-8 sm:h-8',
);

export interface CameraDeviceSelectorProps {}

export const CameraDeviceSelector = (props: CameraDeviceSelectorProps) => {
	const { devices, selectDeviceId, selectedDeviceId } =
		useContext(CameraContext);
	const swapCamera = () => {
		if (selectedDeviceId) {
			const index = devices.findIndex(
				(device) => device.deviceId === selectedDeviceId,
			);
			if (index === -1) {
				return;
			}
			selectDeviceId(devices[(index + 1) % devices.length].deviceId);
		} else {
			selectDeviceId(devices[0].deviceId);
		}
	};

	if (!devices.length || devices.length === 1) return null;
	if (devices.length === 2) {
		return (
			<Button
				size="icon"
				color="ghost"
				className="absolute bottom-2 left-2 text-white"
				onClick={swapCamera}
			>
				<Icon name="refresh" />
			</Button>
		);
	}

	return (
		<Select
			value={selectedDeviceId || 'default'}
			onValueChange={selectDeviceId}
		>
			<SelectTrigger asChild>
				<Button
					size="icon"
					color="ghost"
					className="absolute bottom-2 left-2 text-white"
				>
					<Icon name="refresh" />
				</Button>
			</SelectTrigger>
			<SelectContent>
				{devices.map((device) => (
					<SelectItem key={device.deviceId} value={device.deviceId}>
						{device.label}
					</SelectItem>
				))}
			</SelectContent>
		</Select>
	);
};

function dataURItoFile(dataURI: string) {
	// convert base64/URLEncoded data component to raw binary data held in a string
	var byteString;
	if (dataURI.split(',')[0].indexOf('base64') >= 0)
		byteString = atob(dataURI.split(',')[1]);
	else byteString = unescape(dataURI.split(',')[1]);
	// separate out the mime component
	var mimeString = dataURI.split(',')[0].split(':')[1].split(';')[0];
	// write the bytes of the string to a typed array
	var ia = new Uint8Array(byteString.length);
	for (var i = 0; i < byteString.length; i++) {
		ia[i] = byteString.charCodeAt(i);
	}
	const fileExt = mimeString.split('/')[1];
	return new File([ia], `image.${fileExt}`, { type: mimeString });
}
