import {
	Calendar,
	CalendarDay as BaseCalendarDay,
	CalendarDays,
} from 'calendar-blocks';
import { Button } from '../button.js';
import { Icon } from '../icon.js';
import { useCallback, useState } from 'react';
import { withClassName } from '../../hooks.js';
import classNames from 'clsx';

export interface DatePickerProps {
	value: Date | null;
	onChange: (date: Date | null) => void;
	className?: string;
}

export function DatePicker({
	value,
	onChange,
	className,
	...rest
}: DatePickerProps) {
	const [{ month, year }, setDisplay] = useState(() => ({
		month: new Date().getMonth(),
		year: new Date().getFullYear(),
	}));
	const monthLabel = new Date(year, month).toLocaleDateString('en-US', {
		month: 'long',
		year: 'numeric',
	});

	return (
		<div
			className={classNames(
				'flex flex-col items-center justify-center w-[calc(var(--day-size,32px)*7)]',
				className,
			)}
			{...rest}
		>
			<MonthRow>
				<MonthButton
					size="icon"
					color="ghost"
					onClick={() =>
						setDisplay((cur) => ({
							month: cur.month - 1,
							year: cur.year,
						}))
					}
				>
					<Icon name="arrowLeft" />
				</MonthButton>
				<MonthLabel>{monthLabel}</MonthLabel>
				<MonthButton
					size="icon"
					color="ghost"
					onClick={() =>
						setDisplay((cur) => ({
							month: cur.month + 1,
							year: cur.year,
						}))
					}
				>
					<Icon name="arrowRight" />
				</MonthButton>
			</MonthRow>
			<Calendar
				displayMonth={month}
				displayYear={year}
				value={value}
				onChange={onChange}
				onDisplayChange={setDisplay}
			>
				<CalendarGrid>
					<DayLabels />
					<CalendarDays>
						{(value) => <CalendarDay value={value} key={value.key} />}
					</CalendarDays>
				</CalendarGrid>
			</Calendar>
		</div>
	);
}

export interface DateRangePickerProps {
	value: { start: Date | null; end: Date | null };
	onChange: (value: { start: Date | null; end: Date | null }) => void;
	className?: string;
}

export function DateRangePicker({
	value,
	onChange,
	className,
}: DateRangePickerProps) {
	const [{ month, year }, setDisplay] = useState(() => ({
		month: new Date().getMonth(),
		year: new Date().getFullYear(),
	}));
	const monthLabel = new Date(year, month).toLocaleDateString('en-US', {
		month: 'long',
		year: 'numeric',
	});
	const nextMonth = new Date(year, month + 1);
	const nextMonthLabel = nextMonth.toLocaleDateString('en-US', {
		month: 'long',
		year: 'numeric',
	});
	const onDisplayChange = useCallback(
		({ month: newMonth, year: newYear }: { month: number; year: number }) => {
			/**
			 * Important UX consideration:
			 *
			 * since we are displaying 2 months at once, we don't
			 * always want to change our view if the user's cursor
			 * date moves from one month to another. Specifically,
			 * if they move from the first visible month to the
			 * second visible month, we don't need to change the view,
			 * since they are still within the visible range.
			 * So, we write logic to ignore that case!
			 */
			if (newMonth === month + 1 && newYear === year) {
				return; // ignore movement from the first to the second frame
			}

			setDisplay({
				month: newMonth,
				year: newYear,
			});
		},
		[month, year],
	);

	return (
		<Calendar
			displayMonth={month}
			displayYear={year}
			rangeValue={value}
			onRangeChange={(range) => onChange(range)}
			onDisplayChange={onDisplayChange}
			className={classNames('flex justify-center', className)}
		>
			<RangeLayout>
				<MonthButton
					size="icon"
					color="ghost"
					className="[grid-area:prevMonth]"
					onClick={() =>
						setDisplay((cur) => ({
							month: cur.month - 1,
							year: cur.year,
						}))
					}
				>
					<Icon name="arrowLeft" />
				</MonthButton>
				<MonthLabel className="[grid-area:leftMonth]">{monthLabel}</MonthLabel>
				<MonthLabel className="[grid-area:rightMonth] !hidden !sm:block">
					{nextMonthLabel}
				</MonthLabel>
				<MonthButton
					size="icon"
					color="ghost"
					className="[grid-area:nextMonth]"
					onClick={() =>
						setDisplay((cur) => ({
							month: cur.month + 1,
							year: cur.year,
						}))
					}
				>
					<Icon name="arrowRight" />
				</MonthButton>
				<CalendarGrid className="[grid-area:leftGrid]">
					<DayLabels />
					<CalendarDays>
						{(value) => <CalendarDay value={value} key={value.key} />}
					</CalendarDays>
				</CalendarGrid>
				<CalendarGrid className="[grid-area:rightGrid] !hidden !sm:grid">
					<DayLabels />
					<CalendarDays monthOffset={1}>
						{(value) => <CalendarDay value={value} key={value.key} />}
					</CalendarDays>
				</CalendarGrid>
			</RangeLayout>
		</Calendar>
	);
}

const MonthRow = withClassName(
	'div',
	'flex flex-row justify-between items-center w-full',
);

const MonthLabel = withClassName(
	'span',
	'text-sm font-bold min-w-0 overflow-hidden text-center text-ellipsis',
	'self-center',
);

const MonthButton = withClassName(Button, 'self-center');

const CalendarGrid = withClassName(
	'div',
	'grid grid-cols-[repeat(7,var(--day-size,32px))] [grid-auto-rows:var(--day-size,32px)]',
	'height-[calc(var(--day-size,32px)*7)] rounded overflow-hidden p-2',
);

const CalendarDay = withClassName(
	BaseCalendarDay,
	'border border-solid border-transparent bg-white mr--1px mb--1px relative text-black',
	'flex items-center justify-center transition cursor-pointer',
	'[&[data-highlighted]]:(z-1 outline-accent)',
	'hover:(z-1 outline-accent)',
	'active:(bg-accent-wash rounded)',
	'[&[data-selected]]:(bg-accent-light z-2 rounded)',
	'[&[data-in-range]]:(bg-accent-wash rounded-none z-1)',
	'[&[data-range-start]]:(bg-accent-light rounded-l rounded-r-none z-1)',
	'[&[data-range-end]]:(bg-accent-light rounded-r rounded-l-none z-1)',
	'disabled:(opacity-50 cursor-default)',
	// today dot
	"[&[data-today]]:before:(content-[''] absolute left-[2px] top-[2px] w-[6px] h-[6px] rounded-full bg-primary)",
	'[&[data-top-edge]]:(border-t-gray-5)',
	'[&[data-bottom-edge]]:(border-b-gray-5)',
	'[&[data-first-column]]:(border-l-gray-5)',
	'[&[data-last-column]]:(border-r-gray-5)',
	'[&[data-day-first]]:(border-l-gray-5 rounded-tl)',
	'[&[data-day-last]]:(border-r-gray-5 rounded-br)',
	'[&[data-first-column][data-bottom-edge]]:rounded-bl',
	'[&[data-last-column][data-bottom-edge]]:rounded-br',
	'[&[data-first-column][data-top-edge]]:rounded-tl',
	'[&[data-last-column][data-top-edge]]:rounded-tr',
	'[&[data-different-month]]:[visibility:hidden]',
);

const DayLabel = withClassName(
	'div',
	'flex items-center justify-center text-sm text-gray-6',
);

const DayLabels = () => (
	<>
		<DayLabel>S</DayLabel>
		<DayLabel>M</DayLabel>
		<DayLabel>T</DayLabel>
		<DayLabel>W</DayLabel>
		<DayLabel>T</DayLabel>
		<DayLabel>F</DayLabel>
		<DayLabel>S</DayLabel>
	</>
);

const RangeLayout = withClassName(
	'div',
	'grid [grid-template-areas:"prevMonth_leftMonth_nextMonth""leftGrid_leftGrid_leftGrid"] [grid-template-columns:auto_1fr_auto]',
	'[grid-template-rows:auto_1fr] gap-2',
	'sm:[grid-template-areas:"prevMonth_leftMonth_rightMonth_nextMonth""leftGrid_leftGrid_rightGrid_rightGrid"] sm:[grid-template-columns:auto_1fr_1fr_auto]',
);
